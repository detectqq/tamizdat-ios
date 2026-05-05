//go:build netstack_real

package netstack

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	tamizdat "github.com/detectqq/tamizdat"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Handler implements sing-tun's tun.Handler interface. The gvisor
// stack invokes:
//   - PrepareConnection BEFORE every TCP+UDP flow (we always pass
//     through, hence the no-op return).
//   - NewConnectionEx for each accepted TCP flow (gvisor created the
//     conn; we pump bytes between it and a tamizdat-dialed remote).
//   - NewPacketConnectionEx for each new UDP source (note: udpnat2
//     keys by source.AddrPort so ONE PacketConn carries packets to
//     many destinations — see the per-destination NAT loop below).
type Handler struct {
	client *tamizdat.Client
}

// PrepareConnection is called by the gvisor stack before every flow
// (stack_gvisor_tcp.go:82, stack_gvisor_udp.go:61). Returning
// (nil, nil) makes sing-tun fall through to the user handler path.
//
// We don't currently support direct-route shortcuts (where sing-tun
// would bypass the user handler and route the packet directly out an
// interface) — every flow needs to traverse tamizdat, so direct route
// is never beneficial here.
//
// ICMP path: gvisor registers ICMP handlers; if an ICMP echo arrives
// it would call PrepareConnection with network="icmp"-ish. tamizdat
// doesn't carry ICMP, so we return ErrSkip-equivalent (returning
// (nil, nil) here makes sing-tun queue the flow to the user handler
// — but the user handler doesn't have an ICMP method, so the packet
// is silently dropped at the gvisor demux level. That's the correct
// behaviour for a TCP/UDP-only proxy: ICMP through the tunnel is
// not supported.
func (h *Handler) PrepareConnection(
	network string,
	source M.Socksaddr,
	destination M.Socksaddr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	return nil, nil
}

// NewConnectionEx handles each accepted TCP flow. The conn parameter
// is gvisor's TCP "conn" — net.Conn already; reads pull bytes the
// iOS app sent into the tunnel, writes push bytes back. We dial out
// via tamizdat and bidirectionally pump.
//
// onClose may be nil from the gvisor stack
// (stack_gvisor_tcp.go:94 passes nil hard-coded), so the deferred
// call must guard against it.
func (h *Handler) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	dest := destination.AddrPort()
	if onClose != nil {
		defer onClose(nil)
	}
	defer conn.Close()

	// Drop IPv6 destinations: production tamizdat server has no IPv6
	// uplink, so DialContext would round-trip an HTTP/2 CONNECT only
	// to come back with 502 "dial failed". By RST-ing the stream
	// immediately we make iOS apps fall back to IPv4 within
	// 100-300 ms instead of waiting on tunnel timeouts.
	if dest.Addr().Is6() && !dest.Addr().Is4In6() {
		rtLog(fmt.Sprintf("info: drop IPv6 TCP dest %s (server has no v6 uplink)", dest))
		return
	}

	target := net.JoinHostPort(dest.Addr().Unmap().String(), strconv.Itoa(int(dest.Port())))

	release, ok := acquireDial(ctx)
	if !ok {
		return
	}
	remote, dialErr := h.client.DialContext(ctx, "tcp", target)
	release()
	if dialErr != nil {
		rtLog(fmt.Sprintf("error: TCP dial %s: %v", target, dialErr))
		return
	}
	defer remote.Close()

	relay(conn, remote)
}

// NewPacketConnectionEx handles UDP from one iOS source. Critical
// nuance from sing's udpnat2: the conn parameter is keyed by
// source.AddrPort() ONLY — packets read from it can be bound for
// many different destinations. tamizdat.Client.DialUDP, on the
// other hand, returns a net.PacketConn that is single-target (the
// CONNECT authority). So we maintain a per-destination map of
// open tamizdat UDP streams (Option U1 from the audit), bounded
// LRU cap=128 with 60 s idle and 15 s sweep — values that
// survived production in IPA-A5.
//
// Layered with sing's own udpnat (1024 entries by source.AddrPort,
// hard-coded in udpnat2/service.go:30), the overall NAT capacity
// is 1024 sources × 128 dests worst case — far past anything
// realistic on a single device.
func (h *Handler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	if onClose != nil {
		defer onClose(nil)
	}
	defer conn.Close()

	d := newUDPDemux(ctx, h.client, conn)
	d.run()
}

// udpDemux owns the per-destination tamizdat-UDP map for a single
// iOS source. Multiplexing direction:
//   - Local→remote: read from `conn` (sing PacketConn pumped by
//     gvisor), look up tamizdat connection by destination, dial
//     if absent, write the bytes.
//   - Remote→local: each tamizdat connection has its own goroutine
//     that pumps bytes back through `conn.WritePacket(buf, dest)`.
type udpDemux struct {
	ctx    context.Context
	cancel context.CancelFunc
	client *tamizdat.Client
	conn   N.PacketConn

	mu      sync.Mutex
	entries map[netip.AddrPort]*udpEntry
}

const (
	udpDemuxCap        = 128
	udpEntryIdle       = 60 * time.Second
	udpDemuxSweepEvery = 15 * time.Second
)

type udpEntry struct {
	remote   net.PacketConn
	lastSeen time.Time
	dest     netip.AddrPort
	addr     net.Addr // the dest as net.Addr for tamizdat WriteTo
}

func newUDPDemux(ctx context.Context, client *tamizdat.Client, conn N.PacketConn) *udpDemux {
	dctx, cancel := context.WithCancel(ctx)
	return &udpDemux{
		ctx:     dctx,
		cancel:  cancel,
		client:  client,
		conn:    conn,
		entries: make(map[netip.AddrPort]*udpEntry),
	}
}

func (d *udpDemux) run() {
	defer d.cancel()
	defer d.closeAll()

	go d.sweepLoop()

	// IPA-B1 spec audit (N3): wake the blocked ReadPacket below when
	// the parent ctx cancels. udpnat2's natConn.ReadPacket selects on
	// (packetChan / doneChan / readDeadline.Wait()) — none of which
	// observe Go context. Without this watchdog, every active UDP
	// source's demux goroutine + its 1..128 pumpRemoteToLocal children
	// leak forever after netstack.Stop. SetReadDeadline(now) makes
	// ReadPacket return os.ErrDeadlineExceeded immediately; closeAll
	// then unblocks pumpRemoteToLocal via remote.Close.
	go func() {
		<-d.ctx.Done()
		_ = d.conn.SetReadDeadline(time.Now())
		// Eagerly close all per-destination remotes so any
		// pumpRemoteToLocal goroutines blocked in ReadFrom return
		// within milliseconds instead of waiting up to 60 s for
		// their per-iteration deadline.
		d.closeAll()
	}()

	// Local→remote read loop. Sing's PacketReader.ReadPacket fills
	// a buf.Buffer and returns the destination. We use that to look
	// up / dial the tamizdat stream.
	for {
		if d.ctx.Err() != nil {
			return
		}
		// 64 KiB matches the deleted forwardUDP code's buffer size,
		// which served Speedtest's 1500-byte UDP datagrams plus QUIC
		// jumbo-equivalents fine.
		b := buf.NewSize(65536)
		dest, err := d.conn.ReadPacket(b)
		if err != nil {
			b.Release()
			return
		}
		if !dest.IsValid() {
			b.Release()
			continue
		}
		dKey := dest.AddrPort()

		// IPv6 drop — same rationale as TCP path.
		if dKey.Addr().Is6() && !dKey.Addr().Is4In6() {
			b.Release()
			continue
		}

		entry, ok := d.lookupOrDial(dKey, dest)
		if !ok {
			b.Release()
			continue
		}

		// tamizdat.PacketConn.WriteTo accepts a single-target write;
		// the addr value is required by net.PacketConn but ignored
		// by tamizdat's single-target conn. We pass a real addr for
		// debugability anyway.
		_, _ = entry.remote.WriteTo(b.Bytes(), entry.addr)
		b.Release()
	}
}

func (d *udpDemux) lookupOrDial(key netip.AddrPort, dest M.Socksaddr) (*udpEntry, bool) {
	d.mu.Lock()
	if e, ok := d.entries[key]; ok {
		e.lastSeen = time.Now()
		d.mu.Unlock()
		return e, true
	}
	if len(d.entries) >= udpDemuxCap {
		// Evict oldest (linear scan — udpDemuxCap=128 is small enough
		// that O(N) on miss is ~microseconds; not worth a heap).
		var oldestKey netip.AddrPort
		var oldestAt time.Time
		first := true
		for k, e := range d.entries {
			if first || e.lastSeen.Before(oldestAt) {
				oldestKey = k
				oldestAt = e.lastSeen
				first = false
			}
		}
		if old, ok := d.entries[oldestKey]; ok {
			old.remote.Close()
			delete(d.entries, oldestKey)
		}
	}
	d.mu.Unlock()

	// Dial outside the mutex — DialUDP can take 100s of ms when
	// h2 transports need to spin up.
	release, ok := acquireDial(d.ctx)
	if !ok {
		return nil, false
	}
	target := net.JoinHostPort(key.Addr().Unmap().String(), strconv.Itoa(int(key.Port())))
	remote, err := d.client.DialUDP(d.ctx, target)
	release()
	if err != nil {
		rtLog(fmt.Sprintf("error: UDP dial %s: %v", target, err))
		return nil, false
	}

	e := &udpEntry{
		remote:   remote,
		lastSeen: time.Now(),
		dest:     key,
		addr:     dest.UDPAddr(),
	}

	// Race: another goroutine may have added an entry for this key
	// while we were dialing. Whoever wins keeps theirs; the loser
	// closes its remote and uses the survivor.
	d.mu.Lock()
	if winner, ok := d.entries[key]; ok {
		d.mu.Unlock()
		remote.Close()
		return winner, true
	}
	d.entries[key] = e
	d.mu.Unlock()

	// Spawn the remote→local pump for this entry. It runs until the
	// remote closes (idle eviction calls remote.Close) or ctx cancels.
	go d.pumpRemoteToLocal(e)
	return e, true
}

func (d *udpDemux) pumpRemoteToLocal(e *udpEntry) {
	// 64 KiB buffer matches the local-read side; QUIC payloads are
	// bounded well under this.
	buf2 := make([]byte, 65536)
	for {
		if d.ctx.Err() != nil {
			return
		}
		_ = e.remote.SetReadDeadline(time.Now().Add(udpEntryIdle))
		n, _, err := e.remote.ReadFrom(buf2)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		// Write back to the iOS-side conn. The destination here is
		// the *tamizdat-side dest* (i.e., where the packet is FROM
		// the iOS app's perspective — the remote server it's talking
		// to). We use the original dest we recorded when dialing.
		out := buf.As(buf2[:n])
		_ = d.conn.WritePacket(out, M.SocksaddrFrom(e.dest.Addr(), e.dest.Port()))
	}
}

func (d *udpDemux) sweepLoop() {
	t := time.NewTicker(udpDemuxSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
			d.sweep()
		}
	}
}

func (d *udpDemux) sweep() {
	now := time.Now()
	d.mu.Lock()
	for k, e := range d.entries {
		if now.Sub(e.lastSeen) > udpEntryIdle {
			e.remote.Close()
			delete(d.entries, k)
		}
	}
	d.mu.Unlock()
}

func (d *udpDemux) closeAll() {
	d.mu.Lock()
	for k, e := range d.entries {
		e.remote.Close()
		delete(d.entries, k)
	}
	d.mu.Unlock()
}

// relay is the bidirectional pump for TCP. 32 KiB buffers match
// io.Copy's internal default; 256 KiB was wasteful per-stream on
// the iOS extension (64 streams × 2 dirs × 256 KB = 32 MB just for
// relay buffers — that bit us in IPA-Z).
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(b, a, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(a, b, buf)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
}
