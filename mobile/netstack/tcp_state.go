//go:build netstack_real

package netstack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// TCP state machine for the iOS-NE↔tamizdat shim.
//
// Scope reductions over a "real" TCP (we own both endpoints by design,
// so we strip features that are useless inside our two-endpoint pipe):
//   - NO SACK (basic ACK is enough; iOS kernel falls back gracefully)
//   - NO window scaling beyond fixed rwnd = rxRingSize (4 KiB)
//   - NO fast retransmit (between Go memory and the utun fd, packets
//     don't get lost; if iOS kernel ever does drop on its read path,
//     we'd just drop the connection — fine, iOS app retries TCP at
//     L7)
//   - NO TIME-WAIT (we never reuse 5-tuples within ~MSL because each
//     iOS-app socket spawns a new ephemeral src port)
//   - NO Path MTU discovery (MTU is fixed at 4064)
//   - NO ECN (we ignore CWR/ECE flags from iOS)
//   - NO urgent pointer (drop URG segments silently)
//
// What we DO implement:
//   - SYN → SYN-ACK with announced rwnd = 4 KiB, mss = 1460
//   - ESTABLISHED data flow with rxring backpressure (we ACK only what
//     fits in the ring; iOS kernel respects our rwnd updates)
//   - FIN handshake (FIN from either side advances state correctly)
//   - RST on any state inconsistency / table overflow / dial fail

type tcpState uint8

const (
	stListen     tcpState = iota
	stSynRcvd             // got iOS SYN, sent SYN-ACK; awaiting iOS ACK or data
	stEstablished         // both ACKs in; pumps active
	stFinWait1            // we sent FIN, awaiting iOS ACK
	stFinWait2            // iOS ACK'd our FIN, awaiting iOS FIN
	stCloseWait           // iOS sent FIN, ring drained from our side; we owe FIN
	stLastAck             // we sent FIN, awaiting iOS ACK; closes after
	stClosed              // terminal — flow scheduled for table removal
)

// announceMSS — the MSS we tell iOS in our SYN-ACK MSS option. Conservative
// 1460 = 1500 (Ethernet MTU) − 40 (IPv4+TCP). iOS apps won't try to send
// segments larger than this. We have utun MTU of 4064 so plenty of headroom.
const announceMSS uint16 = 1460

// announceWindow is the rwnd we tell iOS we have free for receiving.
// Caps inbound TCP throughput at ~rxRingSize / RTT. With 4 KiB ring and
// loopback-fast iOS-side RTT this is fine for any single flow; aggregate
// at 128 flows × 4 KiB = 512 KiB of in-flight data, more than the
// upstream tamizdat path can sustain anyway.
const announceWindow uint16 = rxRingSize

// dialTimeout limits how long tamizdat.DialContext can take before we
// RST the iOS-side connection. 10 s matches typical browser dial timeouts.
const dialTimeout = 10 * time.Second

// flowIdleTimeout — flow with no segment activity for this long is
// reaped. iOS apps usually close TCP cleanly via FIN, but if the app
// crashes or gets jetsam'd we won't see FIN. Idle reaper closes us.
const flowIdleTimeout = 60 * time.Second

// tcpFlow is one half-open TCP connection between iOS and our shim.
// Lifetime: created on iOS SYN, destroyed via shutdown() (which closes
// rxring, cancels ctx, shuts remote tamizdat conn).
//
// State transitions are serialized through onSegment() which holds
// f.mu. Pump goroutines read f.remote / write to fd outside the lock,
// using atomic counters and the rxring's own mutex.
type tcpFlow struct {
	tup fivetuple // immutable

	// Sequencing — accessed under f.mu unless noted.
	iss     uint32 // our initial seq we picked at SYN time
	sndNxt  uint32 // next seq we will send to iOS
	rcvNxt  uint32 // next seq we expect from iOS
	mu      sync.Mutex
	state   tcpState
	lastSeen atomic.Int64 // unix nanos; written by onSegment, read by reaper

	// rxring buffers iOS-app→tamizdat data. Allocated lazily in onSYN.
	rxring *rxRing

	// remote is the tamizdat-side net.Conn. Set by dialAndPump goroutine
	// after ESTABLISHED transition. nil before that.
	remote net.Conn

	// ctx is cancelled on shutdown to wake any blocked reads.
	ctx    context.Context
	cancel context.CancelFunc

	// closeOnce guards shutdown() so we never double-close.
	closeOnce sync.Once
}

// onSYN handles the very first packet from iOS. We synthesize SYN-ACK
// immediately (so iOS kernel sees us promptly), THEN spawn dialAndPump
// off the hot path. Hot path: ~3 μs.
//
// The flow MUST already be inserted into tcpTable before onSYN is called,
// because the SYN-ACK send may race with a fast iOS retransmit.
func (f *tcpFlow) onSYN(t *tunnel, segIn parsedTCP) {
	f.mu.Lock()
	if f.state != stListen {
		f.mu.Unlock()
		return
	}

	// Pick our initial sequence number. RFC 793 says random; for our
	// use it doesn't matter since we own both endpoints, but iOS kernel
	// expects nonzero ISS.
	var b [4]byte
	_, _ = rand.Read(b[:])
	f.iss = binary.BigEndian.Uint32(b[:])
	f.sndNxt = f.iss + 1 // SYN consumes 1 seq
	f.rcvNxt = segIn.seq + 1
	f.state = stSynRcvd
	f.rxring = newRxRing()
	f.lastSeen.Store(time.Now().UnixNano())

	// Synthesize SYN-ACK.
	t.sendTCP(f.tup, f.iss, f.rcvNxt, tcpSYN|tcpACK, announceWindow, nil)
	f.mu.Unlock()

	// Off-hot-path: dial tamizdat and start pumps.
	go f.dialAndPump(t)
}

// onSegment handles an established-flow segment from iOS. Path: parse →
// state-machine update → rxring.write (data) → ACK back.
func (f *tcpFlow) onSegment(t *tunnel, seg parsedTCP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastSeen.Store(time.Now().UnixNano())

	// RST from iOS terminates the flow immediately.
	if seg.flags&tcpRST != 0 {
		f.state = stClosed
		go f.shutdown()
		return
	}

	switch f.state {
	case stSynRcvd:
		// Expect ACK of our SYN-ACK to transition to ESTABLISHED.
		// iOS kernel sends bare ACK first; sometimes it carries data
		// piggybacked.
		if seg.flags&tcpACK != 0 && seg.ack == f.sndNxt {
			f.state = stEstablished
			// Fall through to handle any piggybacked data below.
		} else {
			// Stale or out-of-order; drop.
			return
		}
		fallthrough

	case stEstablished:
		// Validate seq matches what we expect. iOS kernel won't send
		// out-of-order over the local utun, but defensive.
		if seg.seq != f.rcvNxt && len(seg.payload) > 0 {
			// Either a retransmit (seq < rcvNxt) or a leap (seq > rcvNxt).
			// For retransmit, ACK with current rcvNxt. For leap, drop.
			if seqLessOrEqual(seg.seq, f.rcvNxt) {
				t.sendTCP(f.tup, f.sndNxt, f.rcvNxt, tcpACK, f.advertisedWindow(), nil)
			}
			return
		}

		// Payload? Write to rxring (blocks if full, but we hold f.mu;
		// instead, write what fits and ACK only that much, leaving the
		// rest for iOS to retransmit when our window opens). With our
		// rwnd-equals-ring invariant this never happens — iOS won't
		// send more than free space.
		if len(seg.payload) > 0 {
			n := f.rxring.write(seg.payload)
			f.rcvNxt += uint32(n)
		}

		// FIN? Mark eof, transition to CloseWait. We owe iOS a FIN-ACK
		// once our pumpInbound finishes draining the ring.
		if seg.flags&tcpFIN != 0 {
			f.rcvNxt++ // FIN consumes 1 seq
			f.rxring.markEOF()
			f.state = stCloseWait
		}

		// Send ACK reflecting current rcvNxt. Bare ACK (no payload).
		t.sendTCP(f.tup, f.sndNxt, f.rcvNxt, tcpACK, f.advertisedWindow(), nil)

	case stFinWait1:
		// Awaiting ACK of our FIN.
		if seg.flags&tcpACK != 0 && seg.ack == f.sndNxt {
			f.state = stFinWait2
		}
		// iOS may also send FIN in same segment.
		if seg.flags&tcpFIN != 0 {
			f.rcvNxt++
			t.sendTCP(f.tup, f.sndNxt, f.rcvNxt, tcpACK, f.advertisedWindow(), nil)
			f.state = stClosed
			go f.shutdown()
		}

	case stFinWait2:
		if seg.flags&tcpFIN != 0 {
			f.rcvNxt++
			t.sendTCP(f.tup, f.sndNxt, f.rcvNxt, tcpACK, f.advertisedWindow(), nil)
			f.state = stClosed
			go f.shutdown()
		}

	case stLastAck:
		if seg.flags&tcpACK != 0 && seg.ack == f.sndNxt {
			f.state = stClosed
			go f.shutdown()
		}

	case stCloseWait:
		// iOS already sent FIN; stray segments are noise. ACK to be polite.
		t.sendTCP(f.tup, f.sndNxt, f.rcvNxt, tcpACK, f.advertisedWindow(), nil)

	case stClosed:
		// Send RST so iOS gives up.
		t.sendTCP(f.tup, f.sndNxt, f.rcvNxt, tcpRST, 0, nil)
	}
}

// advertisedWindow is rxring's free space, capped at rxRingSize. Caller
// holds f.mu (so the rxring length read is consistent with our state).
func (f *tcpFlow) advertisedWindow() uint16 {
	if f.rxring == nil {
		return 0
	}
	free := f.rxring.freeLockedExternal()
	if free > rxRingSize {
		return rxRingSize
	}
	return uint16(free)
}

// freeLockedExternal exposes free() to callers that already hold their
// own external lock. Wraps rxring.mu locking.
func (r *rxRing) freeLockedExternal() int {
	r.mu.Lock()
	n := r.freeLocked()
	r.mu.Unlock()
	return n
}

// dialAndPump runs off the hot path. Dials tamizdat upstream, then starts
// the two pump goroutines (inbound: rxring → remote; outbound: remote →
// synth IP+TCP → fd).
func (f *tcpFlow) dialAndPump(t *tunnel) {
	dctx, cancel := context.WithTimeout(f.ctx, dialTimeout)
	defer cancel()

	release, ok := acquireDial(dctx)
	if !ok {
		f.reset(t)
		return
	}
	target := net.JoinHostPort(f.tup.dst.Addr().Unmap().String(), strconv.Itoa(int(f.tup.dst.Port())))
	conn, err := t.client.DialContext(dctx, "tcp", target)
	release()
	if err != nil {
		rtLog("error: TCP dial " + target + ": " + err.Error())
		f.reset(t)
		return
	}

	f.mu.Lock()
	if f.state != stEstablished && f.state != stSynRcvd {
		// Closed before dial returned.
		f.mu.Unlock()
		conn.Close()
		f.shutdown()
		return
	}
	f.remote = conn
	f.mu.Unlock()

	go f.pumpInbound(t)
	go f.pumpOutbound(t)
}

// pumpInbound: rxring → tamizdat. Drains until ring closes (eof) or
// remote write fails.
func (f *tcpFlow) pumpInbound(t *tunnel) {
	buf := make([]byte, 16*1024)
	for {
		n := f.rxring.read(buf)
		if n == 0 {
			// EOF on ring. Half-close remote: tell tamizdat upstream
			// "no more bytes from us" so it can shut down its writer.
			if c, ok := f.remote.(interface{ CloseWrite() error }); ok {
				_ = c.CloseWrite()
			}
			return
		}
		// Drop into remote. Errors mean upstream gave up; shutdown.
		if _, err := f.remote.Write(buf[:n]); err != nil {
			f.shutdown()
			return
		}
	}
}

// pumpOutbound: tamizdat → synth packets to iOS. Reads up to ~1.4 KB
// per iteration (one MSS), wraps in IP+TCP, writes to fd.
func (f *tcpFlow) pumpOutbound(t *tunnel) {
	buf := make([]byte, int(announceMSS))
	for {
		n, err := f.remote.Read(buf)
		if n > 0 {
			f.mu.Lock()
			seq := f.sndNxt
			f.sndNxt += uint32(n)
			ack := f.rcvNxt
			f.mu.Unlock()
			t.sendTCP(f.tup, seq, ack, tcpACK|tcpPSH, announceWindow, buf[:n])
		}
		if err != nil {
			// Upstream closed or errored. Send our FIN.
			f.mu.Lock()
			seq := f.sndNxt
			ack := f.rcvNxt
			switch f.state {
			case stEstablished:
				f.state = stFinWait1
			case stCloseWait:
				f.state = stLastAck
			default:
				f.mu.Unlock()
				return
			}
			f.sndNxt++ // FIN consumes 1 seq
			f.mu.Unlock()
			t.sendTCP(f.tup, seq, ack, tcpFIN|tcpACK, announceWindow, nil)
			return
		}
	}
}

// reset sends RST to iOS and tears down. Used when we can't satisfy
// the connection (dial fail, table full, etc.).
func (f *tcpFlow) reset(t *tunnel) {
	f.mu.Lock()
	seq := f.sndNxt
	ack := f.rcvNxt
	f.state = stClosed
	f.mu.Unlock()
	t.sendTCP(f.tup, seq, ack, tcpRST|tcpACK, 0, nil)
	f.shutdown()
}

// shutdown is the universal cleanup. Idempotent.
func (f *tcpFlow) shutdown() {
	f.closeOnce.Do(func() {
		f.cancel()
		if f.rxring != nil {
			f.rxring.close()
		}
		if f.remote != nil {
			f.remote.Close()
		}
	})
}

// seqLessOrEqual implements RFC 793's serial number arithmetic with
// 32-bit wraparound. Returns true if a is "earlier than or equal to" b
// in TCP serial order.
func seqLessOrEqual(a, b uint32) bool {
	return int32(a-b) <= 0
}

// newTCPFlow constructs a fresh flow stub for a NEW iOS SYN. It is NOT
// yet inserted into the table (caller does that under tcpTable.insert).
func newTCPFlow(tup fivetuple, parent context.Context) *tcpFlow {
	ctx, cancel := context.WithCancel(parent)
	f := &tcpFlow{
		tup:    tup,
		state:  stListen,
		ctx:    ctx,
		cancel: cancel,
	}
	return f
}

// fivetupleFromIPv4TCP extracts the 5-tuple from an iOS-side IP+TCP
// segment. Caller already parsed both headers.
func fivetupleFromIPv4TCP(ip parsedV4, tcp parsedTCP) fivetuple {
	return fivetuple{
		src: netip.AddrPortFrom(ip.src, tcp.srcPort),
		dst: netip.AddrPortFrom(ip.dst, tcp.dstPort),
	}
}
