package tamizdat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
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
var ErrPoolBackpressure = errors.New("tamizdat: pool at MaxTransports cap")

var poolDebugLog atomic.Bool

func poolLogf(format string, args ...any) {
	if poolDebugLog.Load() {
		log.Printf(format, args...)
	}
}

type connPool struct {
	mu          sync.Mutex
	transports  []*h2Transport
	maxStreams  int
	idleTimeout time.Duration
	createFunc  func(ctx context.Context, class TrafficClass) (*h2Transport, error)
	closed      bool
	closeCh     chan struct{}
	// Multi-conn fallback (#6 / compass P1.2):
	minTransports            int   // pre-warm + reaper target
	maxTransports            int   // hard cap on simultaneous transports
	creating                 int   // transports being dialed outside p.mu
	bytesSoftCap             int64 // close transport at outbound bytes >= cap (0=disabled)
	rotationOverlapAllowance int   // extra transient bulk slots while a capped transport drains
	bulkRR                   int   // round-robin index into transports for bulk getTransport
	liteTransport            *h2Transport
	// strictSingleH2: when true, getTransportForClass(TrafficRealtime)
	// returns bulk directly instead of spawning a lite transport. The
	// transport-wide flipShapeMode(ShapeLite) hook on the bulk transport
	// (set up in client.go when MaxTransports==1) handles the per-flow
	// shape change without a 2nd TCP. Trade-off: HoL on shared TCP.
	strictSingleH2 bool
	// liteSpawnDelay: only spawn a lite transport after a realtime flow
	// has been requested for at least this duration (firstRealtimeNanos
	// timestamps the first request). Filters out short STUN probes.
	// 0 = disabled (legacy behavior, spawn lite immediately).
	liteSpawnDelay      time.Duration
	firstRealtimeNanos  atomic.Int64

	liteCloseDeadline atomic.Int64 // Unix nanos, 0 = not armed
	liteCloseTimer    *time.Timer
	liteCloseMin      time.Duration
	liteCloseMax      time.Duration
	realtime          *RealtimeController
}

// newConnPool creates a connection pool that creates new transports via createFunc.
// minTransports >= 1: pre-warm pool and keep at least N transports alive
// (compass P1.2 multi-conn fallback against TSPU detector #490). bytesSoftCap
// > 0 marks a transport draining once outbound bytes cross threshold.
// strictSingleH2: when true, realtime traffic is routed to the bulk transport
// (with transport-wide shape flip), not to a separate lite transport.
// liteSpawnDelay: defer lite-transport spawn by this duration after first
// realtime request, to filter short STUN probes (only used when !strict).
func newConnPool(maxStreams int, idleTimeout time.Duration, minTransports int, maxTransports int, bytesSoftCap int64, rotationOverlapAllowance int, strictSingleH2 bool, liteSpawnDelay time.Duration, createFunc func(ctx context.Context, class TrafficClass) (*h2Transport, error)) *connPool {
	if minTransports < 1 {
		minTransports = 1
	}
	if maxTransports == 0 {
		maxTransports = minTransports
	}
	if maxTransports < minTransports {
		maxTransports = minTransports
	}
	if rotationOverlapAllowance < 0 {
		if maxTransports == 1 && bytesSoftCap > 0 {
			rotationOverlapAllowance = 1
		} else {
			rotationOverlapAllowance = 0
		}
	}
	p := &connPool{
		strictSingleH2:           strictSingleH2,
		liteSpawnDelay:           liteSpawnDelay,
		maxStreams:               maxStreams,
		idleTimeout:              idleTimeout,
		createFunc:               createFunc,
		closeCh:                  make(chan struct{}),
		minTransports:            minTransports,
		maxTransports:            maxTransports,
		bytesSoftCap:             bytesSoftCap,
		rotationOverlapAllowance: rotationOverlapAllowance,
		liteCloseMin:             45 * time.Second,
		liteCloseMax:             90 * time.Second,
	}

	go p.cleanupLoop()
	go p.reaperLoop()

	return p
}

// getTransport returns a bulk-class transport with available capacity, or
// creates a new bulk transport. Kept for legacy internal callers; V2 traffic
// routing should use getTransportForClass.
func (p *connPool) getTransport(ctx context.Context) (*h2Transport, error) {
	return p.getBulkTransport(ctx)
}

// getTransportForClass routes V2 traffic classes to separate transport buckets.
// Strict mode forces realtime onto the bulk transport (no lite spawn).
// Non-strict mode honours liteSpawnDelay: for the first liteSpawnDelay
// after the very first realtime request, traffic is routed to bulk so a
// short STUN probe never spawns a lite transport. After the delay, the
// regular getLiteTransport path is taken.
func (p *connPool) getTransportForClass(ctx context.Context, class TrafficClass) (*h2Transport, error) {
	if class != TrafficRealtime {
		return p.getBulkTransport(ctx)
	}
	if p.strictSingleH2 {
		return p.getBulkTransport(ctx)
	}
	if p.liteSpawnDelay > 0 {
		now := time.Now().UnixNano()
		first := p.firstRealtimeNanos.Load()
		if first == 0 {
			p.firstRealtimeNanos.CompareAndSwap(0, now)
			first = p.firstRealtimeNanos.Load()
		}
		if time.Duration(now-first) < p.liteSpawnDelay {
			// Still in the warm-up window — route this realtime
			// flow over bulk to avoid lite-spawn on short probes.
			return p.getBulkTransport(ctx)
		}
	}
	return p.getLiteTransport(ctx)
}

// activeSNIs returns the SNIs of all currently-alive transports in the pool.
// Used by client.createTransport to call pickServerNameExcluding so a
// freshly-spawned lite transport gets a different cover SNI than bulk.
func (p *connPool) activeSNIs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.transports) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.transports))
	for _, t := range p.transports {
		if t == nil || t.isClosed() {
			continue
		}
		if t.sni != "" {
			out = append(out, t.sni)
		}
	}
	return out
}

// resetFirstRealtimeNanos zeroes the delay-spawn timestamp. Called when
// activeRealtimeCount drops to 0 so the next realtime burst gets a fresh
// 3-sec warm-up before lite-spawn kicks in.
func (p *connPool) resetFirstRealtimeNanos() {
	p.firstRealtimeNanos.Store(0)
}

func (p *connPool) getBulkTransport(ctx context.Context) (*h2Transport, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, context.Canceled
		}

		if t := p.reserveBulkLocked(); t != nil {
			p.mu.Unlock()
			t.touch()
			return t, nil
		}

		capacity := p.maxTransportsWithRotationOverlapLocked()
		if len(p.transports)+p.creating >= capacity {
			if p.creating > 0 {
				p.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(10 * time.Millisecond):
					continue
				}
			}
			// Inline-cleanup: dead/draining-with-zero-streams transports occupy
			// pool slots but cannot serve new requests. Remove them here so a
			// fresh spawn can proceed instead of erroring out with cap=1.
			// Without this fix, strict mode (cap=1) blocks indefinitely when
			// the single bulk transport gets closed (e.g., server-side reset)
			// until the 60s cleanup tick runs, killing parallel HTTPS apps
			// like Roblox login that retry within seconds.
			//
			// Gated to strict mode only — legacy V1/V2/V3 expect rotation-
			// overlap accounting to backpressure when capacity is exhausted,
			// even with a draining-zero-stream transport sitting in the slot.
			// Tests TestPool_BulkRotationWhileLitePresent and
			// TestPool_V1RotationOverlapZeroBackpressures pin that contract.
			if !p.strictSingleH2 {
				p.mu.Unlock()
				return nil, fmt.Errorf("%w: cap=%d", ErrPoolBackpressure, capacity)
			}
			alive := p.transports[:0:0]
			for _, t := range p.transports {
				if t == nil || t.isClosed() {
					continue
				}
				if t.isDraining() && t.streamCount() == 0 {
					t.close()
					p.clearLiteTransportLocked(t)
					continue
				}
				alive = append(alive, t)
			}
			if len(alive) != len(p.transports) {
				p.transports = alive
				p.updatePoolGaugesLocked()
				if len(p.transports)+p.creating < capacity {
					// Slot freed, retry the spawn loop.
					p.mu.Unlock()
					continue
				}
			}
			p.mu.Unlock()
			return nil, fmt.Errorf("%w: cap=%d", ErrPoolBackpressure, capacity)
		}

		p.creating++
		p.mu.Unlock()

		t, err := p.createFunc(ctx, TrafficBulk)
		p.mu.Lock()
		p.creating--
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		prepareTransportForClass(t, TrafficBulk)
		p.prepareV1BulkShapeMode(t)
		t.bytesSoftCap = randomizedBytesSoftCap(p.bytesSoftCap)
		if !t.reserveStreamSlot() {
			t.close()
			return nil, fmt.Errorf("freshly created transport rejects reservation (closed/drain/cap=0)")
		}

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			t.close()
			return nil, context.Canceled
		}
		if len(p.transports) >= p.maxTransportsWithRotationOverlapLocked() {
			p.mu.Unlock()
			t.close()
			continue
		}
		p.transports = append(p.transports, t)
		p.updatePoolGaugesLocked()
		p.mu.Unlock()

		return t, nil
	}
}

func (p *connPool) maxTransportsWithRotationOverlapLocked() int {
	capacity := p.maxTransports
	if p.rotationOverlapAllowance > 0 && p.hasDrainingBulkLocked() {
		capacity += p.rotationOverlapAllowance
	}
	return capacity
}

func (p *connPool) hasDrainingBulkLocked() bool {
	for _, t := range p.transports {
		if t != nil && t.class == TrafficBulk && t.isDraining() {
			return true
		}
	}
	return false
}

func (p *connPool) prepareV1BulkShapeMode(t *h2Transport) {
	if t == nil || p.maxTransports != 1 || p.realtime == nil {
		return
	}
	// Tier 2.5: only spawn the V1 bulk truba in Lite shape when there is a
	// PROVEN realtime flow (RTP-stickylocked). Reading p.realtime.Mode() —
	// which reflects heuristic activeRealtimeCount including default-promoted
	// background UDP (DNS/QUIC/NTP/mDNS) — caused fresh transports to come
	// up in Lite immediately after reconnect simply because OS background
	// noise was running. The valve is meant to fire only on stickylock.
	if p.realtime.LockedRealtimeCount() > 0 {
		t.flipShapeMode(ShapeLite)
	}
}

func (p *connPool) reserveBulkLocked() *h2Transport {
	n := len(p.transports)
	if n == 0 {
		return nil
	}
	start := p.bulkRR % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		t := p.transports[idx]
		if t.class != TrafficBulk {
			continue
		}
		if t.reserveStreamSlot() {
			p.bulkRR = (idx + 1) % n
			return t
		}
	}
	return nil
}

func (p *connPool) getLiteTransport(ctx context.Context) (*h2Transport, error) {
	if p.maxTransports <= 1 {
		return p.getBulkTransport(ctx)
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, context.Canceled
		}

		p.cancelLiteCloseHysteresisLocked()
		if t := p.liteTransport; t != nil {
			if t.isClosed() {
				p.clearLiteTransportLocked(t)
			} else if t.reserveStreamSlot() {
				p.mu.Unlock()
				t.touch()
				return t, nil
			}
		}

		if len(p.transports)+p.creating >= p.maxTransports {
			if p.creating > 0 {
				p.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(10 * time.Millisecond):
					continue
				}
			}
			p.mu.Unlock()
			return nil, fmt.Errorf("%w: cap=%d", ErrPoolBackpressure, p.maxTransports)
		}

		p.creating++
		p.mu.Unlock()

		t, err := p.createFunc(ctx, TrafficRealtime)
		p.mu.Lock()
		p.creating--
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		prepareTransportForClass(t, TrafficRealtime)
		t.bytesSoftCap = 0
		if !t.reserveStreamSlot() {
			t.close()
			return nil, fmt.Errorf("freshly created lite transport rejects reservation (closed/drain/cap=0)")
		}

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			t.close()
			return nil, context.Canceled
		}
		if existing := p.liteTransport; existing != nil && !existing.isClosed() && !existing.isDraining() {
			p.mu.Unlock()
			t.close()
			continue
		}
		if len(p.transports) >= p.maxTransports {
			p.mu.Unlock()
			t.close()
			continue
		}
		p.transports = append(p.transports, t)
		p.liteTransport = t
		p.updatePoolGaugesLocked()
		poolLogf("[tamizdat] lite transport opened")
		p.mu.Unlock()

		return t, nil
	}
}

func prepareTransportForClass(t *h2Transport, class TrafficClass) {
	if t == nil {
		return
	}
	t.class = class
	if class == TrafficRealtime {
		t.shapeMode.Store(int32(ShapeLite))
	} else {
		t.shapeMode.Store(int32(ShapeFull))
	}
}

func (p *connPool) clearLiteTransportLocked(t *h2Transport) {
	if t != nil && t.class == TrafficRealtime && p.liteTransport == t {
		p.liteTransport = nil
		p.cancelLiteCloseHysteresisLocked()
	}
}

func (p *connPool) cancelLiteCloseHysteresisLocked() {
	if p.liteCloseTimer != nil {
		p.liteCloseTimer.Stop()
		p.liteCloseTimer = nil
	}
	p.liteCloseDeadline.Store(0)
}

func (p *connPool) setRealtimeController(controller *RealtimeController) {
	p.mu.Lock()
	p.realtime = controller
	p.mu.Unlock()
}

// BulkTransportShapeMode returns the actual shape mode of the bulk transport
// (or first bulk if multiple). This is the GROUND-TRUTH wire-shape — what
// outgoing TLS records are actually shaped as. Distinct from RealtimeController.Mode()
// which is intent/controller-state. Returns ShapeFull if no bulk transport exists.
func (p *connPool) BulkTransportShapeMode() ShapeMode {
	if p == nil {
		return ShapeFull
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range p.transports {
		if t == nil || t.class != TrafficBulk || t.isClosed() {
			continue
		}
		return ShapeMode(t.shapeMode.Load())
	}
	return ShapeFull
}

// LiteTransportAlive reports whether a separate lite-class realtime transport
// is currently live (V2/V3 architecture: bulk + dedicated lite truba). Returns
// false for V1 (MaxTransports==1) where there is no separate lite transport —
// the bulk truba flips ShapeMode in-place. Useful for variant-aware GUI lamp
// logic: V1 reads bulk shape, V2/V3 reads this + locked-flow count.
func (p *connPool) LiteTransportAlive() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.liteTransport
	if t == nil {
		return false
	}
	return !t.isClosed() && !t.isDraining()
}

func (p *connPool) flipAllBulkTransports(m ShapeMode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range p.transports {
		if t == nil || t.class != TrafficBulk || t.isClosed() {
			continue
		}
		t.flipShapeMode(m)
	}
}

func (p *connPool) cancelLiteCloseHysteresis() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancelLiteCloseHysteresisLocked()
}

func (p *connPool) armLiteCloseHysteresis() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.liteTransport == nil {
		return
	}
	p.cancelLiteCloseHysteresisLocked()
	delay := p.liteCloseMin
	if p.liteCloseMax > p.liteCloseMin {
		delay = randomDuration(p.liteCloseMin, p.liteCloseMax+time.Nanosecond)
	}
	deadline := time.Now().Add(delay)
	p.liteCloseDeadline.Store(deadline.UnixNano())
	p.liteCloseTimer = time.AfterFunc(delay, p.liteCloseTick)
}

func (p *connPool) liteCloseTick() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.liteCloseTimer = nil
	deadline := p.liteCloseDeadline.Load()
	if deadline == 0 {
		return
	}
	if now := time.Now().UnixNano(); now < deadline {
		delay := time.Duration(deadline - now)
		p.liteCloseTimer = time.AfterFunc(delay, p.liteCloseTick)
		return
	}
	p.liteCloseDeadline.Store(0)

	t := p.liteTransport
	if t == nil {
		return
	}
	if p.realtime != nil && p.realtime.ActiveRealtimeCount() != 0 {
		return
	}
	if t.streamCount() != 0 {
		delay := 10 * time.Millisecond
		deadline := time.Now().Add(delay)
		p.liteCloseDeadline.Store(deadline.UnixNano())
		p.liteCloseTimer = time.AfterFunc(delay, p.liteCloseTick)
		return
	}
	t.markDraining()
	t.close()
	p.removeTransportLocked(t)
	poolLogf("[tamizdat] lite transport closed")
	p.clearLiteTransportLocked(t)
	p.updatePoolGaugesLocked()
}

func (p *connPool) removeTransportLocked(target *h2Transport) {
	if target == nil {
		return
	}
	kept := p.transports[:0]
	for _, t := range p.transports {
		if t != target {
			kept = append(kept, t)
		}
	}
	p.transports = kept
}

func (p *connPool) updatePoolGaugesLocked() {
	bulkAlive := 0
	realtimeAlive := 0
	for _, t := range p.transports {
		if t.isClosed() || t.isDraining() {
			continue
		}
		switch t.class {
		case TrafficRealtime:
			realtimeAlive++
		default:
			bulkAlive++
		}
	}
	setPoolTransportGauges(bulkAlive, realtimeAlive)
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
			p.clearLiteTransportLocked(t)
			continue
		}
		if t.isDraining() && t.streamCount() == 0 {
			t.close()
			p.clearLiteTransportLocked(t)
			continue
		}
		if t.streamCount() == 0 {
			last := t.lastActive()
			if !last.IsZero() && time.Since(last) > p.idleTimeout {
				t.close()
				p.clearLiteTransportLocked(t)
				continue
			}
		}
		alive = append(alive, t)
	}
	p.transports = alive
	p.updatePoolGaugesLocked()
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}

		bulkAlive := 0
		for _, tr := range p.transports {
			if tr.class == TrafficBulk && !tr.isClosed() && !tr.isDraining() {
				bulkAlive++
			}
		}
		if bulkAlive >= p.minTransports || len(p.transports)+p.creating >= p.maxTransportsWithRotationOverlapLocked() {
			p.mu.Unlock()
			return
		}
		p.creating++
		p.mu.Unlock()

		tr, err := p.createFunc(ctx, TrafficBulk)
		p.mu.Lock()
		p.creating--
		p.mu.Unlock()
		if err != nil {
			return
		}
		prepareTransportForClass(tr, TrafficBulk)
		p.prepareV1BulkShapeMode(tr)
		tr.bytesSoftCap = randomizedBytesSoftCap(p.bytesSoftCap)

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			tr.close()
			return
		}
		if len(p.transports) >= p.maxTransportsWithRotationOverlapLocked() {
			p.mu.Unlock()
			tr.close()
			return
		}
		p.transports = append(p.transports, tr)
		p.updatePoolGaugesLocked()
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
	p.cancelLiteCloseHysteresisLocked()

	for _, t := range p.transports {
		t.close()
	}
	p.transports = nil
	setPoolTransportGauges(0, 0)
	return nil
}
