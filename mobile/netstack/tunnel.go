//go:build ios && netstack_real

package netstack

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	tamizdat "github.com/detectqq/tamizdat"

	"github.com/anarki/samizdat-ios/mobile/internal/configparse"
)

// tunnel is the iOS-NE singleton. Owns:
//   - the duped utun fd
//   - the tamizdat client (upstream proxy)
//   - the TCP and UDP flow tables
//   - the pktBufPool (utun read scratch)
//
// One tunnel per netstack.Start call. tunnel.run() is the read loop;
// it serializes IP packet receive but dispatches per-flow work
// asynchronously (TCP onSegment is non-blocking, UDP udpOnPacket is
// non-blocking modulo the rare lock).
type tunnel struct {
	fd     int
	client *tamizdat.Client

	tcp *tcpTable
	udp *udpTable

	pkts *pktPool

	// utunSelf is the tun's own /30 address (172.19.0.1) used when
	// synthesizing reply packets — it's the "from" IP iOS sees on
	// tamizdat→iOS responses.
	utunSelf netip.Addr

	ctx    context.Context
	cancel context.CancelFunc

	// writeMu serializes syscall.Write to the utun fd. Multiple
	// goroutines call sendTCP/sendUDP concurrently; the kernel utun
	// driver doesn't block reads on writes, but writes from many goroutines
	// without serialization can interleave (since each "packet" is one
	// syscall.Write but multiple writes may queue). Single mutex keeps
	// the write path simple. Profile: ~1 μs per held lock — fine.
	writeMu sync.Mutex
}

// utun4Self is the address sing-tun-equivalent code uses as "this
// device's own address inside the tunnel". Must match Swift's
// NEIPv4Settings(addresses:["172.19.0.1"]) and Go-side iosTunInet4.
const utun4Self = "172.19.0.1"

// startTunnel constructs and starts the tunnel. Returns nil on success.
// On failure tears down all partial state.
func startTunnel(ctx context.Context, fd int32, configBlob string) error {
	cfg, err := configparse.Parse(configBlob)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	// Build tamizdat client with V2 mode (300 stream cap; matches
	// IPA-B4 design). Path 5 doesn't change tamizdat config — V2 was
	// already proven necessary for iOS multi-app burst in B4.
	client, err := buildTamizdatClient(cfg, netip.MustParseAddr(utun4Self))
	if err != nil {
		return fmt.Errorf("tamizdat.NewClient: %w", err)
	}
	client.DisableRealtimeDetector()

	// SetMemoryLimit before we start any allocation. Our budget per
	// project_ios_singtun_ground_truth.md memory: 50 MB jetsam ×
	// 3/4 = 37.5 MB heap soft limit. Aggressive on Path 5 where we
	// expect ≤ 25 MB total RSS at 50 flows.
	debug.SetMemoryLimit(int64(37 * 1024 * 1024))
	debug.SetGCPercent(20) // Psiphon production recipe; very aggressive GC

	tctx, tcancel := context.WithCancel(ctx)
	t := &tunnel{
		fd:       int(fd),
		client:   client,
		tcp:      newTCPTable(),
		udp:      newUDPTable(),
		pkts:     newPktPool(),
		utunSelf: netip.MustParseAddr(utun4Self),
		ctx:      tctx,
		cancel:   tcancel,
	}

	// Hand off. tunnel.run() blocks; spin in a goroutine so Start()
	// returns to Swift quickly.
	rtRes = &runResources{tunnel: t}

	go t.run()
	go t.reaperLoop()

	rtLog(fmt.Sprintf("info: netstack started fd=%d server=%s:%d sni=%s mtu=%d (Path 5 / Option A)",
		fd, cfg.ServerHost, cfg.ServerPort, cfg.SNI, tunMTU))
	return nil
}

// run is the main packet dispatch loop. Hot path: read → parse → route.
//
// Termination: ctx cancel triggers run() exit via syscall.Read returning
// EBADF after fd is closed. We close fd on ctx cancel via tearDown.
func (t *tunnel) run() {
	for {
		if t.ctx.Err() != nil {
			return
		}
		buf := t.pkts.get()
		_, ip, err := readUtun(t.fd, buf)
		if err != nil {
			t.pkts.put(buf)
			// fd closed (EBADF) on tearDown — exit cleanly.
			return
		}
		t.dispatch(ip)
		t.pkts.put(buf)
	}
}

// dispatch parses one IP packet and routes to the TCP or UDP path.
// Hot path: one parseIPv4 call, one parseTCP/parseUDP call, one map
// lookup, one method call. ~3-5 μs steady state.
func (t *tunnel) dispatch(ip []byte) {
	v4, ok := parseIPv4(ip)
	if !ok {
		return
	}

	switch v4.proto {
	case protoTCP:
		tcp, ok := parseTCP(v4.payload)
		if !ok {
			return
		}
		tup := fivetupleFromIPv4TCP(v4, tcp)

		// SYN → new flow.
		if tcp.flags&tcpSYN != 0 && tcp.flags&tcpACK == 0 {
			f := newTCPFlow(tup, t.ctx)
			if !t.tcp.insert(tup, f) {
				// Table full. RST iOS-side; iOS app retries / falls
				// back. No alloc beyond the synth packet itself.
				t.sendTCP(tup, 0, tcp.seq+1, tcpRST|tcpACK, 0, nil)
				return
			}
			f.onSYN(t, tcp)
			return
		}

		// Existing flow.
		f := t.tcp.lookup(tup)
		if f == nil {
			// Stray segment for unknown flow. RST so iOS gives up.
			t.sendTCP(tup, 0, tcp.seq+1, tcpRST|tcpACK, 0, nil)
			return
		}
		f.onSegment(t, tcp)

	case protoUDP:
		udp, ok := parseUDP(v4.payload)
		if !ok {
			return
		}
		t.udpOnPacket(v4, udp)

	case protoICMP4:
		// ICMP through tunnel not supported (tamizdat is TCP/UDP only).
		// Drop silently. iOS apps don't usually rely on ICMP through
		// VPN; the host stack handles ping outside the tunnel.
		return
	}
}

// sendTCP synthesizes one IP+TCP packet and writes it to the utun fd.
// The 5-tuple is from the iOS-app perspective (src=ios-app, dst=server);
// the OUTGOING-to-iOS packet swaps these so iOS sees src=server,
// dst=ios-app.
//
// Buffer comes from pkts.put-able pool; released after Write.
func (t *tunnel) sendTCP(tup fivetuple, seq, ack uint32, flags byte, win uint16, payload []byte) {
	bufp := t.pkts.get()
	defer t.pkts.put(bufp)

	// Layout in bufp:
	//   [0:4]      utun AF prefix
	//   [4:24]     IPv4 header
	//   [24:44]    TCP header
	//   [44:end]   payload
	//   end = 4 + 20 + 20 + len(payload)
	const ipStart = utunHdrLen
	const tcpStart = ipStart + ipv4MinHeader
	const dataStart = tcpStart + tcpMinHeader
	end := dataStart + len(payload)
	if end > len(bufp) {
		// Payload too big for one MTU — shouldn't happen because
		// pumpOutbound caps at announceMSS, but defensive.
		return
	}
	if len(payload) > 0 {
		copy(bufp[dataStart:end], payload)
	}

	// Build IPv4 header. src=server (real dst), dst=ios-app (real src).
	srcIP := tup.dst.Addr() // server side
	dstIP := tup.src.Addr() // ios side
	buildIPv4(bufp[ipStart:tcpStart], srcIP, dstIP, protoTCP, end-ipStart)

	// Build TCP header. Ports swap correspondingly.
	buildTCP(bufp[tcpStart:end], tup.dst.Port(), tup.src.Port(), seq, ack, flags, win, srcIP, dstIP, end-tcpStart)

	// Set utun AF prefix (BE uint32 = AF_INET).
	binary.BigEndian.PutUint32(bufp[0:4], afINET)

	t.writeMu.Lock()
	_, _ = syscall.Write(t.fd, bufp[:end])
	t.writeMu.Unlock()
}

// sendUDP synthesizes one IP+UDP packet for tamizdat-side response back
// to iOS. Same buffer layout as sendTCP.
func (t *tunnel) sendUDP(tup fivetuple, payload []byte) {
	bufp := t.pkts.get()
	defer t.pkts.put(bufp)

	const ipStart = utunHdrLen
	const udpStart = ipStart + ipv4MinHeader
	const dataStart = udpStart + udpHeader
	end := dataStart + len(payload)
	if end > len(bufp) {
		return
	}
	copy(bufp[dataStart:end], payload)

	srcIP := tup.dst.Addr()
	dstIP := tup.src.Addr()
	buildIPv4(bufp[ipStart:udpStart], srcIP, dstIP, protoUDP, end-ipStart)
	buildUDP(bufp[udpStart:end], tup.dst.Port(), tup.src.Port(), srcIP, dstIP, end-udpStart)

	binary.BigEndian.PutUint32(bufp[0:4], afINET)

	t.writeMu.Lock()
	_, _ = syscall.Write(t.fd, bufp[:end])
	t.writeMu.Unlock()
}

// reaperLoop periodically scans flow tables for idle entries and
// reaps them. Runs every 15 s per flowIdleTimeout/4 cadence.
func (t *tunnel) reaperLoop() {
	tk := time.NewTicker(15 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tk.C:
			now := time.Now().UnixNano()
			for _, f := range t.tcp.snapshot() {
				if now-f.lastSeen.Load() > int64(flowIdleTimeout) {
					t.tcp.remove(f.tup)
					go f.shutdown()
				}
			}
			cutoff := time.Now().Add(-flowIdleTimeout)
			for _, f := range t.udp.snapshot() {
				if f.lastSeen.Before(cutoff) {
					t.udp.remove(f.tup)
					go f.shutdown()
				}
			}
		}
	}
}

// stopTunnel tears down. Idempotent.
func stopTunnel() {
	if rtRes == nil || rtRes.tunnel == nil {
		return
	}
	t := rtRes.tunnel
	rtRes = nil

	t.cancel()
	t.tcp.closeAll()
	t.udp.closeAll()
	if t.client != nil {
		t.client.Close()
	}
	// Closing fd unblocks the run() loop's syscall.Read with EBADF.
	if t.fd > 0 {
		_ = syscall.Close(t.fd)
	}
	rtLog("info: netstack stopped (Path 5)")
}

// runResources is the package-global state, set by startTunnel and
// cleared by stopTunnel. Replaces the IPA-B4 `resources` struct.
type runResources struct {
	tunnel *tunnel
}

var rtRes *runResources

// buildTamizdatClient constructs the upstream tamizdat.Client with the
// iOS-NE-tuned config from IPA-B4 (V2 mode for multi-app burst headroom).
//
// The utunIP parameter enables the bind() workaround per Apple developer
// thread #681516: outbound TCP connections from inside an iOS NE see a
// 3× perf drop when the remote IP is in includedRoutes (full-tunnel
// default). bind()ing the local socket to the tun's own IP recovers
// ~950 Mbps from ~300 Mbps. tamizdat.ClientConfig.Dialer is the hook
// — see bind_workaround_ios.go for the wrapper.
func buildTamizdatClient(cfg *configparse.Config, utunIP netip.Addr) (*tamizdat.Client, error) {
	clientCfg := tamizdat.ClientConfig{
		ServerAddr:        net.JoinHostPort(cfg.ServerHost, strconv.Itoa(cfg.ServerPort)),
		ServerName:        cfg.SNI,
		PublicKey:         cfg.PubkeyBytes,
		ShortID:           cfg.ShortIDArray,
		Fingerprint:       cfg.Fingerprint,
		MaxStreamsPerConn: 150,
		IdleTimeout:       30 * time.Second,
		PoolVariant:       "v2",
		StrictSingleH2:    false,
		Dialer:            iosBindDialer(utunIP),
	}
	if len(cfg.SNIPool) > 1 {
		clientCfg.ServerNames = cfg.SNIPool
	}
	return tamizdat.NewClient(clientCfg)
}
