package samizdat

import (
	"context"
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
}

// newConnPool creates a connection pool that creates new transports via createFunc.
func newConnPool(maxStreams int, idleTimeout time.Duration, createFunc func(ctx context.Context) (*h2Transport, error)) *connPool {
	p := &connPool{
		maxStreams:  maxStreams,
		idleTimeout: idleTimeout,
		createFunc:  createFunc,
		closeCh:     make(chan struct{}),
	}

	go p.cleanupLoop()

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

	for _, t := range p.transports {
		if !t.isClosed() && !t.isDraining() && t.hasCapacity() {
			p.mu.Unlock()
			t.touch()
			return t, nil
		}
	}

	p.mu.Unlock()

	t, err := p.createFunc(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
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
