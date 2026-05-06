//go:build netstack_real

package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// UDP NAT in Path 5 / Option A.
//
// Our model: each iOS-side UDP datagram arrives as IP+UDP from the utun
// fd. We key by full 5-tuple (iOS-source, real-server-dest). For each
// new key we dial tamizdat.Client.DialUDP(dest), which gives us an
// upstream net.PacketConn that's single-target by tamizdat convention.
//
// Why 5-tuple keying and not just source.AddrPort (the sing-tun udpnat2
// model): tamizdat.DialUDP is single-target per stream; one source can
// talk to many destinations (DNS resolver hits 1.1.1.1, then QUIC hits
// google.com), and we need a separate upstream per destination. Old
// handler.go had this as a 2-level map (source → udpDemux holding per-
// destination map). New design: flat 5-tuple → udpFlow. Simpler;
// memory equivalent.
//
// Memory budget per flow:
//   - udpFlow struct: ~256 B
//   - 1 pumpRemoteToLocal goroutine: ~4 KB stack
//   - 1 borrowed pump-buf from sync.Pool: 16 KB peak (returned on close)
// Total live: ~20 KB worst case. At 128 cap = 2.5 MiB worst case.

const MaxUDPFlows = 128

// pumpReadBufPool reuses the 16 KiB read buffer across all
// pumpRemoteToLocal goroutines. Size 16 KiB is per-IPA-B5 tuning:
// UDP datagrams (DNS, QUIC, game traffic) are bounded ~1.5 KB; 16
// KiB still has 10× headroom. Pool keeps pooled buffers warm; under-
// load excess buffers get GC'd via standard sync.Pool drain.
const pumpReadBufSize = 16 * 1024

var pumpReadBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, pumpReadBufSize)
		return &b
	},
}

// udpFlow lifetime: created on first packet for a new 5-tuple; destroyed
// by idle reaper or shutdown. Pump goroutine reads from upstream remote
// and writes synth IP+UDP back to fd.
type udpFlow struct {
	tup      fivetuple
	remote   net.PacketConn
	lastSeen atomic.Int64
	closeMu  sync.Mutex
	closed   bool
	ctx      context.Context
	cancel   context.CancelFunc
}

// udpTable is the bounded map of 5-tuple → *udpFlow. LRU-evicts oldest
// when at MaxUDPFlows capacity.
type udpTable struct {
	mu      sync.Mutex
	flows   map[fivetuple]*udpFlow
	dialing map[fivetuple]struct{}
}

func newUDPTable() *udpTable {
	return &udpTable{
		flows:   make(map[fivetuple]*udpFlow, MaxUDPFlows),
		dialing: make(map[fivetuple]struct{}, 16),
	}
}

// markDialing returns true if caller is the FIRST to dial this 5-tuple;
// false if a dial is already in flight (caller should drop the packet).
// Also returns false if the flow is already established (caller should
// re-lookup on the next packet).
func (t *udpTable) markDialing(tup fivetuple) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.flows[tup]; ok {
		return false
	}
	if _, ok := t.dialing[tup]; ok {
		return false
	}
	t.dialing[tup] = struct{}{}
	return true
}

// finishDialing removes the 5-tuple from in-flight set. Safe to call
// even if not in set.
func (t *udpTable) finishDialing(tup fivetuple) {
	t.mu.Lock()
	delete(t.dialing, tup)
	t.mu.Unlock()
}

func (t *udpTable) lookup(tup fivetuple) *udpFlow {
	t.mu.Lock()
	f := t.flows[tup]
	if f != nil {
		f.lastSeen.Store(time.Now().UnixNano())
	}
	t.mu.Unlock()
	return f
}

// insert installs a fresh flow. If at cap, evicts oldest. Returns true
// (insert always succeeds; caller tolerates a brief evicted-flow
// shutdown out-of-band).
func (t *udpTable) insert(tup fivetuple, f *udpFlow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.flows) >= MaxUDPFlows {
		// Evict oldest. Linear scan — at MaxUDPFlows=128 this is a few
		// microseconds, far cheaper than maintaining a heap.
		var oldestKey fivetuple
		var oldestAt int64
		first := true
		for k, e := range t.flows {
			ts := e.lastSeen.Load()
			if first || ts < oldestAt {
				oldestKey = k
				oldestAt = ts
				first = false
			}
		}
		if old, ok := t.flows[oldestKey]; ok {
			go old.shutdown()
			delete(t.flows, oldestKey)
		}
	}
	t.flows[tup] = f
}

func (t *udpTable) remove(tup fivetuple) {
	t.mu.Lock()
	delete(t.flows, tup)
	t.mu.Unlock()
}

func (t *udpTable) snapshot() []*udpFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*udpFlow, 0, len(t.flows))
	for _, f := range t.flows {
		out = append(out, f)
	}
	return out
}

func (t *udpTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for tup, f := range t.flows {
		go f.shutdown()
		delete(t.flows, tup)
	}
}

func (t *udpTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// shutdown closes the upstream remote and cancels the pump's ctx.
// Idempotent.
func (f *udpFlow) shutdown() {
	f.closeMu.Lock()
	defer f.closeMu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	f.cancel()
	if f.remote != nil {
		f.remote.Close()
	}
}

// onPacket handles one iOS-side UDP datagram. Hot path:
//   - lookup table for existing flow
//   - if absent: dial tamizdat upstream off-hot-path (caller sees
//     drop-then-iOS-retransmit; OK for UDP)
//   - WriteTo upstream.
func (t *tunnel) udpOnPacket(ip parsedV4, udp parsedUDP) {
	tup := fivetuple{
		src: netip.AddrPortFrom(ip.src, udp.srcPort),
		dst: netip.AddrPortFrom(ip.dst, udp.dstPort),
	}

	// Drop IPv6 destinations. Production tamizdat server has no v6
	// uplink, so DialUDP would round-trip a CONNECT only to fail with
	// 502. By dropping silently, iOS apps fall back to IPv4 within
	// 100-300 ms.
	if tup.dst.Addr().Is6() && !tup.dst.Addr().Is4In6() {
		return
	}

	f := t.udp.lookup(tup)
	if f != nil {
		// Existing flow — write upstream synchronously. tamizdat's
		// PacketConn.WriteTo is non-blocking (queues to H2 stream).
		_, _ = f.remote.WriteTo(udp.payload, &udpAddr{tup.dst})
		return
	}

	if !t.udp.markDialing(tup) {
		// Dial already in flight or flow already exists — drop this
		// packet, iOS app will retransmit.
		return
	}

	// New flow. Spawn dial off-hot-path with a COPY of the payload —
	// the original udp.payload is sliced into the pktBufPool buffer,
	// which gets put back to the pool when dispatch returns. Without
	// the copy, by the time udpDial actually runs (after dial latency
	// on the order of ms), the buffer has been recycled and the
	// payload bytes are garbage. Bug class: use-after-free.
	payloadCopy := make([]byte, len(udp.payload))
	copy(payloadCopy, udp.payload)
	go t.udpDial(tup, payloadCopy)
}

// udpDial does tamizdat.DialUDP and inserts the flow. Drops the FIRST
// packet (passed for completeness but not actually written; we'd need
// to handle the dial-completes-before-app-retransmits race, but iOS
// apps are aggressive on UDP retry so this is fine).
func (t *tunnel) udpDial(tup fivetuple, firstPayload []byte) {
	defer t.udp.finishDialing(tup)
	release, ok := acquireDial(t.ctx)
	if !ok {
		return
	}
	defer release()

	target := net.JoinHostPort(tup.dst.Addr().Unmap().String(), strconv.Itoa(int(tup.dst.Port())))
	dctx, cancel := context.WithTimeout(t.ctx, dialTimeout)
	defer cancel()

	remote, err := t.client.DialUDP(dctx, target)
	if err != nil {
		rtLog(fmt.Sprintf("error: UDP dial %s: %v", target, err))
		return
	}

	fctx, fcancel := context.WithCancel(t.ctx)
	f := &udpFlow{
		tup:    tup,
		remote: remote,
		ctx:    fctx,
		cancel: fcancel,
	}
	f.lastSeen.Store(time.Now().UnixNano())
	t.udp.insert(tup, f)

	// Send the first payload that triggered the dial. Best-effort.
	_, _ = remote.WriteTo(firstPayload, &udpAddr{tup.dst})

	// Spawn the remote→iOS pump.
	go f.pumpRemoteToLocal(t)
}

// pumpRemoteToLocal reads upstream UDP datagrams from tamizdat and synthesizes
// IP+UDP packets back to iOS via fd.Write.
func (f *udpFlow) pumpRemoteToLocal(t *tunnel) {
	defer f.shutdown()
	bufp := pumpReadBufPool.Get().(*[]byte)
	defer pumpReadBufPool.Put(bufp)
	buf := *bufp

	for {
		if f.ctx.Err() != nil {
			return
		}
		_ = f.remote.SetReadDeadline(time.Now().Add(udpFlowIdleTimeout))
		n, _, err := f.remote.ReadFrom(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		// Synthesize IPv4+UDP segment to iOS. Note the SWAP of src/dst:
		// from iOS perspective, this packet is FROM the real server
		// (=our flow's dst) TO the iOS app (=our flow's src).
		t.sendUDP(f.tup, buf[:n])
		f.lastSeen.Store(time.Now().UnixNano())
	}
}

const udpFlowIdleTimeout = 60 * time.Second

// udpAddr is a minimal net.Addr to satisfy WriteTo's signature. tamizdat's
// PacketConn.WriteTo ignores the addr value (single-target dial) but the
// interface still requires net.Addr.
type udpAddr struct {
	addr netip.AddrPort
}

func (a *udpAddr) Network() string { return "udp" }
func (a *udpAddr) String() string  { return a.addr.String() }
