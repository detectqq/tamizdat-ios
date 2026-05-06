//go:build netstack_real

package netstack

import "sync"

// tcpRing is a fixed 4 KiB power-of-two circular byte buffer used as
// the rxring (iOS-app→tamizdat) of a TCP flow.
//
// Why fixed 4 KiB and not bytes.Buffer:
//   - bytes.Buffer grows via doubling (1 KB → 2 KB → 4 KB → 8 KB...).
//     Under burst that's ~14 MB pinned heap at 300 flows.
//   - 4 KiB == TCP rwnd we advertise to iOS in SYN-ACK. Buffer-vs-window
//     equality is a load-bearing invariant: iOS apps never send more
//     than the window we advertise; we never advertise more than what
//     fits in the ring.
//   - Power-of-two means index wraparound via & (size-1) instead of %.
//
// Memory accounting:
//   - rxring: 4 KiB pool buffer (returned to pool on flow close)
//   - txring: 2 KiB inline (smaller; outbound from tamizdat side typically
//     stays well-fed because we read as fast as the iOS app drains)
const (
	rxRingSize = 4096
	txRingSize = 2048
	rxRingMask = rxRingSize - 1
	txRingMask = txRingSize - 1
)

type rxRing struct {
	// buf is *[4096]byte from rxRingPool. nil means closed/freed.
	buf  *[rxRingSize]byte
	head uint32 // next slot to read FROM (drain to tamizdat)
	tail uint32 // next slot to write TO (data from iOS app)
	mu   sync.Mutex
	cond *sync.Cond // signals reader when data available or eof
	eof  bool       // FIN observed from iOS side; reader drains then exits
}

func newRxRing() *rxRing {
	r := &rxRing{
		buf: rxRingPool.Get().(*[rxRingSize]byte),
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// length returns occupied bytes. Caller holds r.mu.
func (r *rxRing) lengthLocked() int {
	return int(r.tail - r.head)
}

func (r *rxRing) freeLocked() int {
	return rxRingSize - r.lengthLocked()
}

// write copies up to len(p) bytes into the ring. Returns bytes actually
// written (may be < len(p) if ring full). Signals readers.
func (r *rxRing) write(p []byte) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buf == nil {
		return 0
	}
	free := r.freeLocked()
	n := len(p)
	if n > free {
		n = free
	}
	if n == 0 {
		return 0
	}
	tailIdx := r.tail & rxRingMask
	first := rxRingSize - int(tailIdx)
	if first > n {
		first = n
	}
	copy(r.buf[tailIdx:], p[:first])
	if first < n {
		copy(r.buf[:n-first], p[first:n])
	}
	r.tail += uint32(n)
	r.cond.Broadcast()
	return n
}

// read drains up to len(p) bytes. Blocks until data available or eof.
// Returns 0 only on close+empty.
func (r *rxRing) read(p []byte) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if r.buf == nil {
			return 0
		}
		avail := r.lengthLocked()
		if avail > 0 {
			n := len(p)
			if n > avail {
				n = avail
			}
			headIdx := r.head & rxRingMask
			first := rxRingSize - int(headIdx)
			if first > n {
				first = n
			}
			copy(p[:first], r.buf[headIdx:int(headIdx)+first])
			if first < n {
				copy(p[first:n], r.buf[:n-first])
			}
			r.head += uint32(n)
			// Signal writers (TCP onSegment) that space opened.
			r.cond.Broadcast()
			return n
		}
		if r.eof {
			return 0
		}
		r.cond.Wait()
	}
}

// markEOF tells readers that no more data will arrive after the
// already-buffered bytes drain. Triggered by iOS-side FIN.
func (r *rxRing) markEOF() {
	r.mu.Lock()
	r.eof = true
	r.cond.Broadcast()
	r.mu.Unlock()
}

// close releases the buffer to the pool. Subsequent read/write return 0.
// Idempotent.
func (r *rxRing) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buf != nil {
		rxRingPool.Put(r.buf)
		r.buf = nil
	}
	r.eof = true
	r.cond.Broadcast()
}

// rxRingPool is sync.Pool for the 4 KiB ring buffers. New() allocates
// on miss; pooled instances are reused without zeroing (callers reset
// head/tail to 0 on get).
var rxRingPool = sync.Pool{
	New: func() any {
		var b [rxRingSize]byte
		return &b
	},
}

// txRing is the outbound (tamizdat→iOS) side. Smaller because the iOS
// app drains into kernel TCP buffer fast (we Write() to fd which is
// effectively kernel-side; no rate-limiting from us).
//
// We don't actually need a ring on the txside in this design — we write
// directly to fd in pumpOutbound. Kept here as an empty stub for
// symmetry; if profiling shows we want backpressure, fill in similarly.
