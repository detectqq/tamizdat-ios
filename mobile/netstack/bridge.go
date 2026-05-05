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
	"github.com/sagernet/sing/common/logger"

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

// iOS NEPacketTunnelProvider supplies a 1280-byte MTU via
// `settings.mtu = 1280` in PacketTunnelProvider.swift. The gvisor
// link MTU must match exactly or fdbased reads truncate frames at
// the kernel level.
const iosTunMTU uint32 = 1280

// iOS extension assigns 198.18.0.1/24 to the utun via
// NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks:
// ["255.255.255.0"]). The gvisor stack MUST be told about this
// address so its NIC accepts inbound packets from the iOS-side
// app.
var iosTunInet4 = netip.MustParsePrefix("198.18.0.1/24")

// bridgeStart is called by netstack.Start under the runtime mutex.
// It builds the tamizdat client, opens sing-tun on the iOS-supplied
// utun fd (without trying to set system routes — iOS's
// NEPacketTunnelNetworkSettings owns those), and starts the gvisor
// stack with our Handler.
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

	// sing-tun darwin: when Options.FileDescriptor != 0 the
	// constructor SKIPS the open-utun-socket path and just dups our
	// fd into a *os.File. EXP_ExternalConfiguration: true skips
	// setRoutes() in Start() (which on iOS extension lacks
	// privileges) and skips InterfaceMonitor wiring (which on iOS
	// is nil and would nil-panic). See tun_darwin.go:148-154 for
	// the Start() short-circuit and 156-165 for Close().
	tunOpts := tun.Options{
		Name:                      "utun",
		FileDescriptor:            int(fd),
		MTU:                       iosTunMTU,
		Inet4Address:              []netip.Prefix{iosTunInet4},
		AutoRoute:                 false,
		EXP_ExternalConfiguration: true,
		Logger:                    logger.NOP(),
	}
	tunIf, err := tun.New(tunOpts)
	if err != nil {
		client.Close()
		return fmt.Errorf("tun.New: %w", err)
	}

	handler := &Handler{client: client}
	// IPA-B2: switch from forced "gvisor" to "" (auto). With the
	// with_gvisor build tag and IncludeAllNetworks=false, sing-tun's
	// auto-selector picks Mixed (system TCP + gvisor UDP) — the
	// same mode sing-box-for-apple ships on iOS, and what
	// Shadowrocket/Hiddify/V2Box use to hit 150+ Mbps.
	//
	// The "gvisor" mode has an iOS-specific TCP buffer cap at
	// stack_gvisor.go:182-202 (32 KiB default / 128 KiB max via a
	// runtime.GOOS=="ios" check). At 200 Mbps × ~30 ms RTT, BDP =
	// 750 KB; the 128 KiB cap pins throughput at ~32 Mbps —
	// matching the 30 Mbps we measured in IPA-B1. Mixed mode
	// routes TCP through a localhost net.Listener (kernel TCP, no
	// gvisor buffer cap) that our Handler.NewConnectionEx already
	// serves; UDP stays on gvisor + udpnat + our udpDemux. The
	// Handler interface is unchanged.
	//
	// Bonus: this also drops gvisor's per-flow TCP recv/send
	// arenas from our process memory, recovering ~3 MB at the
	// 32-stream-speedtest fanout point that pushed IPA-B1 over
	// the 50 MB jetsam cap when Roblox launched.
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
		Logger:     logger.NOP(),
	})
	if err != nil {
		_ = tunIf.Close()
		client.Close()
		return fmt.Errorf("tun.NewStack(gvisor): %w", err)
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

	rtLog(fmt.Sprintf("info: netstack started fd=%d server=%s:%d sni=%s mtu=%d",
		fd, cfg.ServerHost, cfg.ServerPort, cfg.SNI, iosTunMTU))
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
