//go:build netstack_real

package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	tamizdat "github.com/detectqq/tamizdat"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"

	"github.com/anarki/samizdat-ios/mobile/internal/configparse"
)

// resources holds everything the netstack package needs to keep
// alive between Start() and Stop(). Stored under runtime.mu in
// netstack.go.
type resources struct {
	tunIf  tun.Tun
	stack  tun.Stack
	client *tamizdat.Client
}

// rtRes is the active resources bundle. Set by bridgeStart, cleared
// by bridgeStop. Guarded by netstack.go's runtime.mu.
var (
	rtResMu sync.Mutex
	rtRes   *resources
)

// IPA-B3: switched MTU 1280 → 4064 to match sing-box-for-apple's
// iOS NEPacketTunnelProvider default (`protocol/tun/inbound.go:107`
// in sing-box source — "above 4064 the tun loop performance drops
// significantly, may be a system bug; below 4064 means more iovec
// scratch and 3-4× syscalls per byte"). At MTU=1280 sing-tun's
// `batchSize := ((512*1024)/MTU)+1 = 410` slots × `buf.NewSize` of
// 32 KiB each = ~26 MiB of tun-loop scratch alone. With MTU=4064
// + the with_low_memory build tag, that drops to ~4 MiB.
const iosTunMTU uint32 = 4064

// IPA-B3: switched 198.18.0.1/24 → 172.19.0.1/30 to match
// sing-box-for-apple's documented default at
// `docs/configuration/inbound/tun.md:162`. /30 = 4-host subnet
// (.0,.1,.2,.3); System/Mixed stack uses .1 as listener bind, .2
// as spoofed source. Both /24 and /30 satisfy
// `HasNextAddress(prefix,1) == true` (stack_system.go:82-87 check
// that fails the start). Switch to /30 for parity with the proven
// reference implementation.
var iosTunInet4 = netip.MustParsePrefix("172.19.0.1/30")

// bridgeStart is called by netstack.Start under the runtime mutex.
// It builds the tamizdat client, opens sing-tun on the iOS-supplied
// utun fd, and starts the Mixed stack with our Handler.
//
// On failure all partially-constructed resources are torn down here;
// caller's `cancel()` then frees the ctx. On success the resources
// are stashed in `rtRes` for bridgeStop.
func bridgeStart(ctx context.Context, fd int32, configBlob string) error {
	cfg, err := configparse.Parse(configBlob)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	client, err := buildTamizdatClient(cfg)
	if err != nil {
		return fmt.Errorf("build tamizdat client: %w", err)
	}
	// IPA-A7 carry-forward: the client-side realtime detector's
	// per-packet Observe under d.mu was the hottest mutex at
	// speedtest pps. Operator measured no user-perceptible RTT
	// difference (117 vs 116 ms) — server-side Tier 1/2 classifier
	// independently decides realtime per its own packet timing.
	client.DisableRealtimeDetector()

	// IPA-B3: tun.Options aligned with sing-box-for-apple iOS defaults
	// (sing-box `protocol/tun/inbound.go:186-222` + `:181`).
	//
	// Key decisions:
	//   - FileDescriptor != 0: tun.New skips the "create utun" path
	//     and just dups our fd via os.NewFile (tun_darwin.go:94-122).
	//   - EXP_ExternalConfiguration: true: keeps Start() from calling
	//     `setRoutes()` (no privileges in NE sandbox; would fail
	//     silently anyway) AND skips the
	//     `t.options.InterfaceMonitor.RegisterMyInterface(name)` call
	//     at tun_darwin.go:152 — we don't pass an InterfaceMonitor,
	//     so without this short-circuit the call would nil-panic.
	//     sing-box-for-apple does NOT set EXP_ExternalConfiguration
	//     because they DO pass a non-nil InterfaceMonitor (libbox-
	//     managed); we keep it true while we use a minimal stack.
	//   - EXP_MultiPendingPackets: true (Darwin batchLoopDarwin
	//     enables vectored iovec syscalls, ~3-4× fewer syscalls
	//     per packet). sing-box-for-apple sets this on iOS+Mixed
	//     when MTU<=9000 (`inbound.go:181`).
	tunOpts := tun.Options{
		Name:                      "utun",
		FileDescriptor:            int(fd),
		MTU:                       iosTunMTU,
		Inet4Address:              []netip.Prefix{iosTunInet4},
		AutoRoute:                 false,
		EXP_ExternalConfiguration: true,
		EXP_MultiPendingPackets:   true,
		Logger:                    newStackLogger(),
	}
	tunIf, err := tun.New(tunOpts)
	if err != nil {
		client.Close()
		return fmt.Errorf("tun.New: %w", err)
	}

	// IPA-B3: ForwarderBindInterface + InterfaceFinder are the
	// load-bearing knobs sing-box-for-apple sets at
	// `protocol/tun/inbound.go:319,326-327`. Without them the System
	// TCP NAT's listener.Listen at stack_system.go:117-128 fires
	// through the kernel default route instead of being bound to the
	// tun interface — packets loop back into our own stack →
	// connections never establish. This is the #1 root cause of the
	// IPA-B2 "Roblox / speedtest don't open" symptom.
	//
	// We use sing's `control.NewDefaultInterfaceFinder()` which
	// resolves interfaces via `net.Interfaces()`. sing-box-for-apple
	// uses a richer libbox-managed monitor that pulls from Swift's
	// NWPathMonitor; for our minimal build the default finder is
	// sufficient because the only resolution we need is "given the
	// tun's name, find its index" — and `net.Interfaces()` returns
	// the tun once it's up.
	ifFinder := control.NewDefaultInterfaceFinder()
	if err := ifFinder.Update(); err != nil {
		// Don't fail bridgeStart on this — Update() reads
		// net.Interfaces() which may transiently fail during iOS
		// extension cold start. The finder will be re-queried per
		// dial inside BindToInterface0; tunIf isn't even up yet at
		// this point in some cases.
		rtLog(fmt.Sprintf("warn: InterfaceFinder.Update() at startup: %v (will retry per-dial)", err))
	}

	handler := &Handler{client: client}
	stack, err := tun.NewStack("", tun.StackOptions{
		Context:    ctx,
		Tun:        tunIf,
		TunOptions: tunOpts,
		// UDPTimeout aligns with our per-entry udpDemux idle (60 s).
		// sing's udpnat2 caps source-keyed entries at 1024 hard-coded;
		// our per-source per-destination map (cap=128, 60s idle, 15s
		// sweep) sits inside one udpnat slot.
		UDPTimeout: udpEntryIdle,
		Handler:    handler,
		// Real logger so sing-tun's "bind forwarder to interface:
		// <err>" warning at stack_system.go:117-128 reaches our App
		// Group log file. NOP() in IPA-B2 hid this exact warning
		// which would have surfaced the missing
		// ForwarderBindInterface field.
		Logger:                 newStackLogger(),
		ForwarderBindInterface: true,
		InterfaceFinder:        ifFinder,
	})
	if err != nil {
		_ = tunIf.Close()
		client.Close()
		return fmt.Errorf("tun.NewStack: %w", err)
	}
	if err := stack.Start(); err != nil {
		_ = stack.Close()
		_ = tunIf.Close()
		client.Close()
		return fmt.Errorf("stack.Start: %w", err)
	}

	rtResMu.Lock()
	rtRes = &resources{tunIf: tunIf, stack: stack, client: client}
	rtResMu.Unlock()

	// IPA-B3: start the FreeOSMemory watchdog. Without it Go's GC
	// holds onto unused arenas for minutes after deallocation, which
	// pushed IPA-B1/B2 over the 50 MB iOS jetsam cap during heavy
	// alloc spikes (Speedtest + Roblox launch). The watchdog
	// tick-checks runtime.MemStats.Sys every 5 s and calls
	// debug.FreeOSMemory() when sys > 45 MiB. Mirrors
	// sing-box-for-apple's oomkiller cadence
	// (service/oomkiller/timer.go:39,160,215).
	startMemWatch(ctx)

	rtLog(fmt.Sprintf("info: netstack started fd=%d server=%s:%d sni=%s mtu=%d nic=%s",
		fd, cfg.ServerHost, cfg.ServerPort, cfg.SNI, iosTunMTU, iosTunInet4))
	return nil
}

func buildTamizdatClient(cfg *configparse.Config) (*tamizdat.Client, error) {
	// Mirror mobile/socksstub/socksstub.go:336-407 V1 production
	// posture (which has been live on operator's iPhone since IPA-Z).
	// Specifically:
	//   - MaxStreamsPerConn=150 (IPA-A9 cap; ~19 MiB worst-case
	//     per-stream live state on Go h2 + tamizdat at ~130 KB/stream).
	//   - IdleTimeout=30s (faster transport reap than tamizdat's 5min
	//     default; brief load spikes don't pin extras across the
	//     50 MB jetsam cap).
	//   - PoolVariant=v1 + StrictSingleH2=true: locks pool to
	//     exactly 1 TCP/443, no rotation, max-1 entry in TSPU #546
	//     counter. Realtime classifier still runs and flips bulk
	//     transport's shapeMode to Lite for ALL streams during a
	//     realtime flow, then back to Full after hysteresis.
	//   - DisableDefaultSecurity NOT set: tamizdat's applyDefaults
	//     turns on TCPFragmentation + RecordFragmentation for DPI
	//     camouflage. Setting DisableDefaultSecurity defeats those —
	//     production socksstub deliberately leaves it false.
	clientCfg := tamizdat.ClientConfig{
		ServerAddr:        net.JoinHostPort(cfg.ServerHost, strconv.Itoa(cfg.ServerPort)),
		ServerName:        cfg.SNI,
		PublicKey:         cfg.PubkeyBytes,
		ShortID:           cfg.ShortIDArray,
		Fingerprint:       cfg.Fingerprint,
		MaxStreamsPerConn: 150,
		IdleTimeout:       30 * time.Second,
		PoolVariant:       "v1",
		StrictSingleH2:    true,
	}
	if len(cfg.SNIPool) > 1 {
		clientCfg.ServerNames = cfg.SNIPool
	}
	return tamizdat.NewClient(clientCfg)
}

// bridgeStop releases all resources stashed by bridgeStart. Idempotent
// — second call is a no-op. Order is important: stack.Close detaches
// the gvisor link endpoint (which holds the fd indirectly via fdbased)
// BEFORE tunIf.Close which actually closes the fd. Reversing this order
// would let the fdbased dispatcher panic on EBADF.
func bridgeStop() {
	rtResMu.Lock()
	res := rtRes
	rtRes = nil
	rtResMu.Unlock()

	if res == nil {
		return
	}
	// Order: stack first (drains gvisor goroutines, detaches link),
	// THEN tun (closes fd), THEN client (closes tamizdat transports).
	if res.stack != nil {
		_ = res.stack.Close()
	}
	if res.tunIf != nil {
		_ = res.tunIf.Close()
	}
	if res.client != nil {
		res.client.Close()
	}
	rtLog("info: netstack stopped")
}
