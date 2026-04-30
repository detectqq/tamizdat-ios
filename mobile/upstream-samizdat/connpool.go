package samizdat

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// connPool manages a pool of H2 transports to a server, tracking active
// stream counts and cleaning up idle connections.
//
// Design note (audit fix): the previous implementation closed any transport
// whose streamCount was 0 every 30 s regardless of the configured
// IdleTimeout. For a SOCKS5 client serving a browsing session (lots of
// short streams) this produced a cadence of TCP 443 reconnects — exactly
// the per-IP behaviour TSPU #546 polices. This version
//
//	(a) only reaps a zero-stream transport after it has been idle for
//	    IdleTimeout wallclock (default 5 m, set by ClientConfig), and
//	(b) uses a slower tick (60 s) so the pool does not itself emit a 30 s
//	    heartbeat signature.
type connPool struct {
	mu          sync.Mutex
	transports  []*h2Transport
	maxStreams  int
	idleTimeout time.Duration
	createFunc  func(ctx context.Context) (*h2Transport, error)
	closed      bool
	closeCh     chan struct{}
	// Multi-conn fallback (#6 / compass P1.2):
	minTransports int   // pre-warm + reaper target
	bytesSoftCap  int64 // close transport at outbound bytes >= cap (0=disabled)
	nextRR        int   // round-robin index into transports for getTransport
}

// newConnPool creates a connection pool that creates new transports via createFunc.
// minTransports >= 1: pre-warm pool and keep at least N transports alive
// (compass P1.2 multi-conn fallback against TSPU detector #490). bytesSoftCap
// > 0 marks a transport draining once outbound bytes cross threshold.
func newConnPool(maxStreams int, idleTimeout time.Duration, minTransports int, bytesSoftCap int64, createFunc func(ctx context.Context) (*h2Transport, error)) *connPool {
	if minTransports < 1 {
		minTransports = 1
	}
	p := &connPool{
		maxStreams:    maxStreams,
		idleTimeout:   idleTimeout,
		createFunc:    createFunc,
		closeCh:       make(chan struct{}),
		minTransports: minTransports,
		bytesSoftCap:  bytesSoftCap,
	}

	go p.cleanupLoop()
	go p.reaperLoop()

	return p
}

// getTransport returns an existing transport with available capacity, or
// creates a new one.
func (p *connPool) getTransport(ctx context.Context) (*h2Transport, error) {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return nil, context.Canceled
	}

	// Round-robin pick across existing transports so traffic is distributed
	// instead of piling onto the first available (compass P1.2). Combined
	// with HIGH-4 atomic CAS reservation: even if two callers see the same
	// rr index, reserveStreamSlot ensures only one gets the slot.
	n := len(p.transports)
	if n > 0 {
		start := p.nextRR % n
		for i := 0; i < n; i++ {
			t := p.transports[(start+i)%n]
			if t.reserveStreamSlot() {
				p.nextRR = (start + i + 1) % n
				p.mu.Unlock()
				t.touch()
				return t, nil
			}
		}
	}

	p.mu.Unlock()

	t, err := p.createFunc(ctx)
	if err != nil {
		return nil, err
	}
	// #6 multi-conn fallback: propagate soft-cap to the fresh transport.
	t.bytesSoftCap = p.bytesSoftCap
	// Pre-reserve a slot on the freshly-created transport so the caller can
	// safely openTunnel without racing the next getTransport caller.
	if !t.reserveStreamSlot() {
		t.close()
		return nil, fmt.Errorf("freshly created transport rejects reservation (closed/drain/cap=0)")
	}

	p.mu.Lock()
	// MED-5: if the pool was Closed while we were dialing outside the lock,
	// don't add the new transport to a dead pool -- close it immediately.
	if p.closed {
		p.mu.Unlock()
		t.close()
		return nil, context.Canceled
	}
	p.transports = append(p.transports, t)
	p.mu.Unlock()

	return t, nil
}

// cleanupLoop periodically removes closed and idle transports. The tick
// interval is intentionally looser than the client-visible IdleTimeout to
// avoid being the 30 s heartbeat observable.
func (p *connPool) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.closeCh:
			return
		}
	}
}

// cleanup removes closed transports and closes ones that have been idle for
// longer than idleTimeout. A transport is "idle" only when it has zero
// active streams AND its lastActive timestamp is older than idleTimeout.
func (p *connPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	alive := make([]*h2Transport, 0, len(p.transports))
	for _, t := range p.transports {
		if t.isClosed() {
			continue
		}
		if t.isDraining() && t.streamCount() == 0 {
			t.close()
			continue
		}
		if t.streamCount() == 0 {
			last := t.lastActive()
			if !last.IsZero() && time.Since(last) > p.idleTimeout {
				t.close()
				continue
			}
		}
		alive = append(alive, t)
	}
	p.transports = alive
}


// reaperLoop tops up the pool to minTransports. If the byte soft-cap was hit
// on a transport (drained itself), reaper notices and dials a replacement.
// Heartbeat 5s -- not too aggressive (don't burn dial budgets) but fast
// enough to recover from a TSPU-induced transport teardown within ~5s.
func (p *connPool) reaperLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.closeCh:
			return
		case <-t.C:
			p.topUp()
			p.observeCurtainSignal()
		}
	}
}

// observeCurtainSignal samples bytes-per-flow buckets and emits a debug-only
// hint if the 5-15KB bucket starts dominating (= #490 enforcement signal).
// Deliberately does NOT auto-adjust MinTransports -- operator decides:
// expanding the pool is the right move under #490 but the wrong move under
// #546 (parallel TLS-conn policing), and detecting which is which requires
// active probing the operator may not want to authorise. This is a tuning
// hint, not a control loop.
func (p *connPool) observeCurtainSignal() {
	// Use the package-level expvars directly instead of forking telemetry plumbing.
	if bytesPerFlow5_15KB == nil || bytesPerFlowSub5KB == nil {
		return
	}
	mid := bytesPerFlow5_15KB.Value()
	low := bytesPerFlowSub5KB.Value()
	if mid < 50 {
		return
	}
	// If 5-15KB closures outnumber sub-5KB by >2x, it's the #490 signature.
	if mid > 2*low {
		// Future: emit log line via a registered logf hook. For now the hint
		// is observable via the buckets alone in /debug/vars; operators with
		// MinTransports=1 should consider raising it to 3-4 with
		// BytesPerTransportSoftCap=10000 to ride out the #490 curtain.
		_ = mid
	}
}

// topUp dials new transports until len(transports) >= minTransports.
// Best-effort: dial errors silent (next tick retries). Caller must NOT hold
// p.mu (createFunc dials outside the lock).
func (p *connPool) topUp() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	alive := 0
	for _, tr := range p.transports {
		if !tr.isClosed() && !tr.isDraining() {
			alive++
		}
	}
	need := p.minTransports - alive
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < need; i++ {
		tr, err := p.createFunc(ctx)
		if err != nil {
			return
		}
		tr.bytesSoftCap = p.bytesSoftCap
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			tr.close()
			return
		}
		p.transports = append(p.transports, tr)
		p.mu.Unlock()
	}
}

// close shuts down all transports in the pool.
func (p *connPool) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true
	close(p.closeCh)

	for _, t := range p.transports {
		t.close()
	}
	p.transports = nil
	return nil
}
