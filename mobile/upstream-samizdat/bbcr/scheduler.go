package bbcr

import (
	"context"
	"errors"
	"expvar"
	"sort"
	"sync"
	"time"
)

const (
	AckStallSuspectThreshold  = 750 * time.Millisecond
	AckStallCautiousThreshold = 2 * time.Second
	AckStallUnackedThreshold  = 16 * 1024
	DefaultPingInterval       = 10 * time.Second
	DefaultPingTimeout        = 15 * time.Second
	DefaultCleanExitWindow    = 30 * time.Second
	DefaultPinnedCautiousTTL  = time.Minute
	DefaultDRRQuantum         = 1200
	DefaultACKCoalesceDelay   = 100 * time.Millisecond
)

var ErrSchedulerBackpressure = errors.New("bbcr: scheduler backpressure")

var (
	schedulerTransitionActiveToSuspect   = expvar.NewInt("samizdat.bbcr.scheduler.mode_transitions_active_to_suspect")
	schedulerTransitionSuspectToCautious = expvar.NewInt("samizdat.bbcr.scheduler.mode_transitions_suspect_to_cautious")
	schedulerTransitionCautiousToPinned  = expvar.NewInt("samizdat.bbcr.scheduler.mode_transitions_cautious_to_pinned")
	schedulerTransitionCleanExitToActive = expvar.NewInt("samizdat.bbcr.scheduler.mode_transitions_to_active_clean_exit")
	schedulerTransitionPinnedToCautious  = expvar.NewInt("samizdat.bbcr.scheduler.mode_transitions_pinned_to_cautious_recovery")
	schedulerCurrentMode                 = expvar.NewString("samizdat.bbcr.scheduler.current_mode")
	schedulerPrewarmAttempts             = expvar.NewInt("samizdat.bbcr.scheduler.prewarm_attempts")
	schedulerPrewarmDialTokenDenied      = expvar.NewInt("samizdat.bbcr.scheduler.prewarm_dial_token_denied")
	schedulerPrewarmDialSucceeded        = expvar.NewInt("samizdat.bbcr.scheduler.prewarm_dial_succeeded")
	schedulerAssignFrameBackpressure     = expvar.NewInt("samizdat.bbcr.scheduler.assign_frame_backpressure")
	schedulerTeardownsPastPrewarm        = expvar.NewInt("samizdat.bbcr.scheduler.transport_teardowns_past_prewarm")
	schedulerOuterRotations              = expvar.NewInt("samizdat.bbcr.scheduler.outer_rotations")
	schedulerACKStallObservations        = expvar.NewInt("samizdat.bbcr.scheduler.ack_stall_observations")
	schedulerRTOObservations             = expvar.NewInt("samizdat.bbcr.scheduler.rto_observations")
)

type FrameClass uint8

const (
	FrameClassControl FrameClass = iota
	FrameClassRetransmit
	FrameClassFreshData
)

type ScheduleOptions struct {
	Class      FrameClass
	AvoidEpoch uint32
}

type SchedulerConfig struct {
	Clock        Clock
	DialGate     DialGate
	DialKey      DialKey
	Transports   []Transport
	CapEstimator CapEstimator
	Rand         int63Source
	Policy       CapPolicy
	Prewarm      func(context.Context) (Transport, error)
	PingInterval time.Duration
	PingTimeout  time.Duration
	CleanExit    time.Duration
	PinnedTTL    time.Duration
	DRRQuantum   uint64
	// AlwaysCautious forces permanent cautious mode. It is an emergency kill
	// switch for deployments where the passive detector is suspected of missing
	// a real TSPU freeze.
	AlwaysCautious bool
}

type Scheduler struct {
	mu                sync.Mutex
	transportCond     *sync.Cond
	clock             Clock
	gate              DialGate
	dialKey           DialKey
	transports        map[uint32]Transport
	order             []uint32
	est               CapEstimator
	rng               int63Source
	policy            CapPolicy
	prewarm           func(context.Context) (Transport, error)
	pingInterval      time.Duration
	pingTimeout       time.Duration
	cleanExit         time.Duration
	pinnedTTL         time.Duration
	drrQuantum        uint64
	alwaysCautious    bool
	mode              SessionState
	lastACKProgress   time.Time
	cleanSince        time.Time
	cautiousSince     time.Time
	pinnedSince       time.Time
	rtoByStream       map[uint32][]time.Time
	teardowns         []time.Time
	pingTimeouts      []time.Time
	prewarmInFlight   bool
	freshOuterPending bool
	freshOuterEpoch   uint32
	closed            bool
}

func NewScheduler(cfg SchedulerConfig) *Scheduler {
	clk := cfg.Clock
	if clk == nil {
		clk = RealClock{}
	}
	est := cfg.CapEstimator
	if est == nil {
		est = NewConservativeCapEstimator(DefaultFixedS2CBudget)
	}
	rng := cfg.Rand
	if rng == nil {
		rng = secureInt63Source{}
	}
	policy := cfg.Policy
	if policy.HardCap == 0 {
		var err error
		policy, err = NewRandomizedCapPolicyWithRand(rng)
		if err != nil {
			policy = CapPolicy{SoftCap: 8000, PrewarmTrigger: 10000, HardCap: HardCapPcap}
		}
	}
	now := clk.Now()
	mode := SessionActive
	if cfg.AlwaysCautious {
		mode = SessionCautious
	}
	s := &Scheduler{
		clock: clk, gate: cfg.DialGate, dialKey: cfg.DialKey, transports: make(map[uint32]Transport), est: est, rng: rng, policy: policy, prewarm: cfg.Prewarm,
		pingInterval: positiveDuration(cfg.PingInterval, DefaultPingInterval), pingTimeout: positiveDuration(cfg.PingTimeout, DefaultPingTimeout), cleanExit: positiveDuration(cfg.CleanExit, DefaultCleanExitWindow), pinnedTTL: positiveDuration(cfg.PinnedTTL, DefaultPinnedCautiousTTL),
		drrQuantum: positiveUint64(cfg.DRRQuantum, DefaultDRRQuantum), alwaysCautious: cfg.AlwaysCautious, mode: mode, lastACKProgress: now, cleanSince: now, rtoByStream: make(map[uint32][]time.Time),
	}
	s.transportCond = sync.NewCond(&s.mu)
	for _, tr := range cfg.Transports {
		s.addTransportLocked(tr, false)
	}
	setSchedulerCurrentMode(mode)
	return s
}

func positiveUint64(v, d uint64) uint64 {
	if v > 0 {
		return v
	}
	return d
}

func (s *Scheduler) AddTransport(tr Transport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addTransportLocked(tr, true)
}

func (s *Scheduler) addTransportLocked(tr Transport, countRotation bool) {
	if tr == nil {
		return
	}
	epoch := tr.Epoch()
	if _, exists := s.transports[epoch]; !exists {
		if countRotation && len(s.order) > 0 {
			schedulerOuterRotations.Add(1)
			if tr.State() == TransportActive {
				s.freshOuterPending = true
				s.freshOuterEpoch = epoch
			}
		}
		s.order = append(s.order, epoch)
		sort.Slice(s.order, func(i, j int) bool { return s.order[i] < s.order[j] })
	}
	s.transports[epoch] = tr
	s.transportCond.Broadcast()
}

func (s *Scheduler) Mode() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

func (s *Scheduler) PrewarmThreshold() uint64        { return s.policy.PrewarmTrigger }
func (s *Scheduler) PingBaseInterval() time.Duration { return s.pingInterval }

func (s *Scheduler) FreshOuterPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.freshOuterPending
}

func (s *Scheduler) ClearFreshOuterPending() {
	s.mu.Lock()
	s.freshOuterPending = false
	s.freshOuterEpoch = 0
	s.mu.Unlock()
}

func (s *Scheduler) clearFreshOuterPendingFor(epoch uint32) {
	s.mu.Lock()
	if s.freshOuterPending && s.freshOuterEpoch == epoch {
		s.freshOuterPending = false
		s.freshOuterEpoch = 0
	}
	s.mu.Unlock()
}

func (s *Scheduler) markPrewarmInFlight() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prewarmInFlight {
		return false
	}
	s.prewarmInFlight = true
	return true
}

func (s *Scheduler) clearPrewarmInFlight() {
	s.mu.Lock()
	s.prewarmInFlight = false
	s.mu.Unlock()
}

func (s *Scheduler) Close() {
	s.mu.Lock()
	s.closed = true
	s.transports = nil
	s.order = nil
	s.mu.Unlock()
}

// SnapshotActiveEpochs returns the set of epochs whose transports are presently
// in TransportActive state. Used by server-side Prewarm to identify whether a
// later WaitForTransport completion was satisfied by a NEW outer rather than an
// already-existing one.
func (s *Scheduler) SnapshotActiveEpochs() map[uint32]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[uint32]struct{}, len(s.transports))
	for epoch, tr := range s.transports {
		if tr != nil && tr.State() == TransportActive {
			out[epoch] = struct{}{}
		}
	}
	return out
}

// AnyActiveTransport returns any transport currently in TransportActive state,
// preferring the one with the largest RemainingPcapBudget. Returns nil if none
// is alive. Used by server-side Prewarm to pick a transport on which to emit a
// MAY_REBIND advisory frame.
func (s *Scheduler) AnyActiveTransport() Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best Transport
	bestBudget := uint64(0)
	for _, tr := range s.transports {
		if tr == nil || tr.State() != TransportActive {
			continue
		}
		b := tr.RemainingPcapBudget()
		if best == nil || b > bestBudget {
			best, bestBudget = tr, b
		}
	}
	return best
}

// FirstNewActiveTransport returns the first TransportActive transport whose
// epoch is NOT in old. Used by server-side Prewarm to identify the freshly
// attached outer after WaitForTransport returns. Prefers the largest budget.
func (s *Scheduler) FirstNewActiveTransport(old map[uint32]struct{}) Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best Transport
	bestBudget := uint64(0)
	for epoch, tr := range s.transports {
		if tr == nil || tr.State() != TransportActive {
			continue
		}
		if _, isOld := old[epoch]; isOld {
			continue
		}
		b := tr.RemainingPcapBudget()
		if best == nil || b > bestBudget {
			best, bestBudget = tr, b
		}
	}
	return best
}

// WaitForNewTransport blocks until a TransportActive transport whose epoch is
// NOT in `known` is added to the scheduler, or ctx times out. Used by the
// server-side Prewarm callback so it doesn't immediately return on the same
// already-depleted outer that triggered the prewarm. Added in P0.5 Cycle 3.2.
func (s *Scheduler) WaitForNewTransport(ctx context.Context, known map[uint32]struct{}) (Transport, error) {
	hasFresh := func() Transport {
		var best Transport
		bestBudget := uint64(0)
		for epoch, tr := range s.transports {
			if tr == nil || tr.State() != TransportActive {
				continue
			}
			if _, isOld := known[epoch]; isOld {
				continue
			}
			b := tr.RemainingPcapBudget()
			if best == nil || b > bestBudget {
				best, bestBudget = tr, b
			}
		}
		return best
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if tr := hasFresh(); tr != nil {
		return tr, nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		deadline, ok = ctx.Deadline()
	}
	if !ok {
		return nil, context.DeadlineExceeded
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, context.DeadlineExceeded
	}
	timer := time.AfterFunc(remaining, func() {
		s.mu.Lock()
		s.transportCond.Broadcast()
		s.mu.Unlock()
	})
	defer timer.Stop()
	for {
		if tr := hasFresh(); tr != nil {
			return tr, nil
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timer.Reset(remaining)
		s.transportCond.Wait()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
}

// WaitForTransport blocks until a transport with TransportActive state is
// available in the scheduler, or ctx times out. Used by Stream.sendFrame to
// wait for client-driven REBIND to deliver a fresh outer after backpressure.
func (s *Scheduler) WaitForTransport(ctx context.Context) error {
	hasActive := func() bool {
		for _, tr := range s.transports {
			if tr != nil && tr.State() == TransportActive {
				return true
			}
		}
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if hasActive() {
		return nil
	}
	// Set deadline.
	deadline, ok := ctx.Deadline()
	if !ok {
		// No deadline — impose 5s max.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		deadline, ok = ctx.Deadline()
	}
	if !ok {
		return context.DeadlineExceeded
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	// Use a timer so we don't block Cond.Wait forever.
	timer := time.AfterFunc(remaining, func() {
		s.mu.Lock()
		s.transportCond.Broadcast()
		s.mu.Unlock()
	})
	defer timer.Stop()
	for {
		if hasActive() {
			return nil
		}
		// Re-arm timer before each wait iteration.
		remaining = time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		timer.Reset(remaining)
		s.transportCond.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (s *Scheduler) AssignFrame(ctx context.Context, f Frame, opts ScheduleOptions) (Transport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	estimate := s.est.EstimateFrameS2C(f)
	tr := s.chooseTransport(f, opts, estimate)
	if tr == nil {
		var err error
		tr, err = s.tryPrewarm(ctx, estimate, f, opts)
		if err != nil {
			return nil, err
		}
	}
	if tr == nil {
		schedulerAssignFrameBackpressure.Add(1)
		return nil, ErrSchedulerBackpressure
	}
	if s.enforcesBudget() && tr.RemainingPcapBudget() < estimate {
		schedulerAssignFrameBackpressure.Add(1)
		return nil, ErrSchedulerBackpressure
	}
	if opts.Class == FrameClassFreshData && tr.State() != TransportActive {
		schedulerAssignFrameBackpressure.Add(1)
		return nil, ErrSchedulerBackpressure
	}
	f.Header.TransportEpoch = tr.Epoch()
	if err := tr.SendFrame(ctx, f); err != nil {
		return nil, err
	}
	if opts.Class == FrameClassRetransmit {
		s.clearFreshOuterPendingFor(tr.Epoch())
	}
	if observer, ok := s.est.(interface{ ObserveFrameS2C(Frame) uint64 }); ok {
		observer.ObserveFrameS2C(f)
	}
	if opts.Class == FrameClassFreshData && s.enforcesBudget() {
		remaining := tr.RemainingPcapBudget()
		nextFrameCost := uint64(MaxDataPayload) + FramePcapOverhead
		controlReserve := FramePcapOverhead
		retransmitReserve := uint64(MaxDataPayload) + FramePcapOverhead
		minReserveBeforeTrigger := nextFrameCost + controlReserve + retransmitReserve
		if remaining < minReserveBeforeTrigger && s.markPrewarmInFlight() {
			go func() {
				defer s.clearPrewarmInFlight()
				_, _ = s.tryPrewarm(context.Background(), 0, Frame{}, ScheduleOptions{Class: FrameClassControl})
			}()
		}
	}
	return tr, nil
}

func (s *Scheduler) chooseTransport(f Frame, opts ScheduleOptions, estimate uint64) Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best Transport
	bestBudget := uint64(0)
	preferAvoid := opts.Class == FrameClassRetransmit && opts.AvoidEpoch != 0
	enforceBudget := s.mode != SessionActive
	if !enforceBudget {
		var fallback Transport
		for _, epoch := range s.order {
			tr := s.transports[epoch]
			if tr == nil || tr.State() == TransportClosed {
				continue
			}
			if opts.Class == FrameClassFreshData && tr.State() != TransportActive {
				continue
			}
			if preferAvoid && epoch != opts.AvoidEpoch {
				return tr
			}
			if fallback == nil {
				fallback = tr
			}
		}
		return fallback
	}
	for _, epoch := range s.order {
		tr := s.transports[epoch]
		if tr == nil || tr.State() == TransportClosed {
			continue
		}
		if opts.Class == FrameClassFreshData && tr.State() != TransportActive {
			continue
		}
		budget := tr.RemainingPcapBudget()
		if budget < estimate {
			continue
		}
		if preferAvoid && epoch != opts.AvoidEpoch {
			if best == nil || best.Epoch() == opts.AvoidEpoch || budget > bestBudget {
				best, bestBudget = tr, budget
			}
			continue
		}
		if best == nil || (!preferAvoid && budget > bestBudget) {
			best, bestBudget = tr, budget
		}
	}
	return best
}

func (s *Scheduler) tryPrewarm(ctx context.Context, estimate uint64, f Frame, opts ScheduleOptions) (Transport, error) {
	s.mu.Lock()
	prewarm := s.prewarm
	gate := s.gate
	key := s.dialKey
	now := s.clock.Now()
	s.mu.Unlock()
	schedulerPrewarmAttempts.Add(1)
	if prewarm == nil {
		schedulerAssignFrameBackpressure.Add(1)
		return nil, ErrSchedulerBackpressure
	}
	if gate != nil && !gate.TryAcquire(key, now) {
		schedulerPrewarmDialTokenDenied.Add(1)
		schedulerAssignFrameBackpressure.Add(1)
		return nil, ErrSchedulerBackpressure
	}
	tr, err := prewarm(ctx)
	if err != nil {
		return nil, err
	}
	if tr == nil {
		schedulerAssignFrameBackpressure.Add(1)
		return nil, ErrSchedulerBackpressure
	}
	s.AddTransport(tr)
	if estimate > 0 && tr.RemainingPcapBudget() < estimate {
		schedulerAssignFrameBackpressure.Add(1)
		return nil, ErrSchedulerBackpressure
	}
	schedulerPrewarmDialSucceeded.Add(1)
	return tr, nil
}

func (s *Scheduler) ObserveACK(ev ACKEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Time.IsZero() {
		ev.Time = s.clock.Now()
	}
	if ev.NewlyAckedBytes > 0 {
		s.lastACKProgress = ev.Time
		if ev.UnackedBytes == 0 {
			s.cleanSince = ev.Time
		}
	}
}

func (s *Scheduler) CheckACKStall(unacked uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if unacked <= AckStallUnackedThreshold {
		return
	}
	schedulerACKStallObservations.Add(1)
	stall := now.Sub(s.lastACKProgress)
	if stall >= AckStallCautiousThreshold {
		s.enterModeLocked(SessionCautious, now)
		return
	}
	if stall >= AckStallSuspectThreshold {
		s.enterModeLocked(SessionSuspect, now)
	}
}

func (s *Scheduler) CheckCleanExit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if (s.mode == SessionSuspect || s.mode == SessionCautious) && !s.alwaysCautious && !s.cleanSince.IsZero() && now.Sub(s.cleanSince) >= s.cleanExit {
		old := s.mode
		s.mode = SessionActive
		s.rtoByStream = make(map[uint32][]time.Time)
		s.pingTimeouts = nil
		recordSchedulerTransition(old, SessionActive)
		setSchedulerCurrentMode(SessionActive)
	}
	if s.mode == SessionPinnedCautious && !s.pinnedSince.IsZero() && now.Sub(s.pinnedSince) >= s.pinnedTTL {
		old := s.mode
		s.mode = SessionCautious
		s.cautiousSince = now
		// P0.5 Cycle 3.2 hysteresis fix (validator audit d31a51a): when decaying
		// from pinned-cautious back to cautious, reset cleanSince so the
		// cautious->active timer starts fresh from this transition. Without this
		// reset, cleanSince retains a stale value from before the pinning, which
		// can either fire cautious->active immediately (premature recovery) or
		// never fire if cleanSince was zero. Also reset pinnedSince to avoid
		// repeated re-evaluation. Detector hysteresis is therefore an explicit
		// two-step decay: pinned -> cautious (after pinnedTTL) -> active (after
		// cleanExit of clean ACK progress).
		s.cleanSince = now
		s.pinnedSince = time.Time{}
		recordSchedulerTransition(old, SessionCautious)
		setSchedulerCurrentMode(SessionCautious)
	}
}

func (s *Scheduler) ObserveRTO(ev RTOEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	schedulerRTOObservations.Add(1)
	if ev.Time.IsZero() {
		ev.Time = s.clock.Now()
	}
	cutoff30 := ev.Time.Add(-30 * time.Second)
	cutoff5m := ev.Time.Add(-5 * time.Minute)
	list := s.rtoByStream[ev.StreamID]
	kept := list[:0]
	for _, ts := range list {
		if ts.After(cutoff5m) || ts.Equal(cutoff5m) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, ev.Time)
	s.rtoByStream[ev.StreamID] = kept
	within30, within5m := 0, 0
	for _, ts := range kept {
		if ts.After(cutoff30) || ts.Equal(cutoff30) {
			within30++
		}
		if ts.After(cutoff5m) || ts.Equal(cutoff5m) {
			within5m++
		}
	}
	if within5m >= 3 || ev.Attempt >= 3 {
		s.enterModeLocked(SessionPinnedCautious, ev.Time)
	} else if within30 >= 2 || ev.Attempt >= 2 {
		s.enterModeLocked(SessionCautious, ev.Time)
	} else {
		s.enterModeLocked(SessionSuspect, ev.Time)
	}
}

type TransportTeardownEvent struct {
	Epoch        uint32
	EmittedBytes uint64
	Err          error
	Expected     bool
	Time         time.Time
}

func (s *Scheduler) ObserveTransportTeardown(ev TransportTeardownEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Expected {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = s.clock.Now()
	}
	if ev.EmittedBytes < s.policy.PrewarmTrigger {
		return
	}
	schedulerTeardownsPastPrewarm.Add(1)
	cutoff := ev.Time.Add(-60 * time.Second)
	kept := s.teardowns[:0]
	for _, ts := range s.teardowns {
		if ts.After(cutoff) || ts.Equal(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, ev.Time)
	s.teardowns = kept
	if len(kept) >= 2 {
		s.enterModeLocked(SessionPinnedCautious, ev.Time)
		return
	}
	s.enterModeLocked(SessionCautious, ev.Time)
}

func (s *Scheduler) ObservePingTimeout(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.IsZero() {
		now = s.clock.Now()
	}
	if now.Sub(s.lastACKProgress) < AckStallCautiousThreshold {
		return
	}
	cutoff := now.Add(-60 * time.Second)
	kept := s.pingTimeouts[:0]
	for _, ts := range s.pingTimeouts {
		if ts.After(cutoff) || ts.Equal(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	s.pingTimeouts = kept
	if len(kept) >= 2 {
		s.enterModeLocked(SessionCautious, now)
	} else {
		s.enterModeLocked(SessionSuspect, now)
	}
}

func (s *Scheduler) enterModeLocked(mode SessionState, now time.Time) {
	if s.alwaysCautious && mode != SessionTeardown {
		mode = SessionCautious
	}
	if s.mode == SessionPinnedCautious && mode != SessionTeardown {
		return
	}
	if mode < s.mode && s.mode != SessionSuspect {
		return
	}
	old := s.mode
	if old == mode {
		return
	}
	s.mode = mode
	recordSchedulerTransition(old, mode)
	setSchedulerCurrentMode(mode)
	switch mode {
	case SessionCautious:
		s.cautiousSince = now
		// P0.5 Cycle 3.2 flap fix: zero cleanSince when (re-)entering Cautious.
		// ObserveACK sets cleanSince during healthy active-mode traffic; without
		// this reset, CheckCleanExit fires cautious->active immediately on the
		// next tick (since now - cleanSince >= cleanExit using the old stamp),
		// causing ~1 transition/sec steady-state flap under ambient load. Zero
		// out so the cautious->active timer requires a FRESH clean ACK after
		// entering Cautious.
		s.cleanSince = time.Time{}
	case SessionPinnedCautious:
		s.pinnedSince = now
		s.cleanSince = time.Time{}
	case SessionSuspect:
		s.cleanSince = time.Time{}
	}
}

func (s *Scheduler) enforcesBudget() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode != SessionActive
}

func schedulerModeString(mode SessionState) string {
	switch mode {
	case SessionActive:
		return "active"
	case SessionSuspect:
		return "suspect"
	case SessionCautious:
		return "cautious"
	case SessionPinnedCautious:
		return "pinned-cautious"
	case SessionTeardown:
		return "teardown"
	default:
		return "initializing"
	}
}

func setSchedulerCurrentMode(mode SessionState) {
	schedulerCurrentMode.Set(schedulerModeString(mode))
}

func recordSchedulerTransition(old, next SessionState) {
	switch {
	case old == SessionActive && next == SessionSuspect:
		schedulerTransitionActiveToSuspect.Add(1)
	case old == SessionSuspect && next == SessionCautious:
		schedulerTransitionSuspectToCautious.Add(1)
	case old == SessionActive && next == SessionCautious:
		schedulerTransitionSuspectToCautious.Add(1)
	case old == SessionPinnedCautious && next == SessionCautious:
		// P0.5 Cycle 3.2: pinned-cautious decayed back to cautious via pinnedTTL
		// (recovery half-step). Distinct from the cautious->pinned escalation
		// counter so dashboards can tell escalation from recovery.
		schedulerTransitionPinnedToCautious.Add(1)
	case next == SessionPinnedCautious:
		schedulerTransitionCautiousToPinned.Add(1)
	case next == SessionActive:
		schedulerTransitionCleanExitToActive.Add(1)
	}
}

func (s *Scheduler) NextPingInterval() time.Duration {
	s.mu.Lock()
	base := s.pingInterval
	rng := s.rng
	s.mu.Unlock()
	span := int64(base / 5) // ±20%.
	if span <= 0 {
		return base
	}
	delta := positiveMod(rng.Int63(), 2*span+1) - span
	return base + time.Duration(delta)
}

type ACKCoalescer struct {
	mu      sync.Mutex
	clock   Clock
	delay   time.Duration
	pending map[uint32]pendingACK
}

type pendingACK struct {
	ackOffset uint64
	due       time.Time
}

func NewACKCoalescer(clock Clock, delay time.Duration) *ACKCoalescer {
	if clock == nil {
		clock = RealClock{}
	}
	if delay <= 0 {
		delay = DefaultACKCoalesceDelay
	}
	return &ACKCoalescer{clock: clock, delay: delay, pending: make(map[uint32]pendingACK)}
}

func (c *ACKCoalescer) ObserveDataNeedsACK(streamID uint32, ackOffset uint64, reverseDataAvailable bool) (Frame, bool) {
	if reverseDataAvailable {
		c.mu.Lock()
		delete(c.pending, streamID)
		c.mu.Unlock()
		return Frame{Header: FrameHeader{Version: Version1, Type: FrameDATA, HeaderLen: HeaderLenV1, StreamID: streamID, AckOffset: ackOffset, Flags: FlagAckPiggyback}}, true
	}
	c.mu.Lock()
	now := c.clock.Now()
	p := c.pending[streamID]
	if ackOffset > p.ackOffset {
		p.ackOffset = ackOffset
	}
	if p.due.IsZero() {
		p.due = now.Add(c.delay)
	}
	c.pending[streamID] = p
	c.mu.Unlock()
	return Frame{}, false
}

func (c *ACKCoalescer) DueACKs(now time.Time) []Frame {
	if now.IsZero() {
		now = c.clock.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Frame, 0, len(c.pending))
	for streamID, p := range c.pending {
		if now.Before(p.due) {
			continue
		}
		out = append(out, Frame{Header: FrameHeader{Version: Version1, Type: FrameACK, HeaderLen: HeaderLenV1, StreamID: streamID, AckOffset: p.ackOffset, Flags: FlagPriorityControl}})
		delete(c.pending, streamID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Header.StreamID < out[j].Header.StreamID })
	return out
}

type StreamDemand struct {
	StreamID    uint32
	Bytes       uint64
	Interactive bool
}

func (s *Scheduler) SelectStreamsDRR(demands []StreamDemand, rounds int) map[uint32]int {
	served := make(map[uint32]int)
	if rounds <= 0 || len(demands) == 0 {
		return served
	}
	type drrState struct {
		demand  StreamDemand
		deficit uint64
		left    uint64
	}
	states := make([]drrState, 0, len(demands))
	for _, d := range demands {
		if d.StreamID == 0 || d.Bytes == 0 {
			continue
		}
		states = append(states, drrState{demand: d, left: d.Bytes})
	}
	quantum := s.drrQuantum
	for r := 0; r < rounds; r++ {
		progress := false
		for i := range states {
			st := &states[i]
			if st.left == 0 {
				continue
			}
			q := quantum
			if st.demand.Interactive {
				q *= 2
			}
			st.deficit += q
			chunk := st.left
			if chunk > uint64(MaxDataPayload) {
				chunk = uint64(MaxDataPayload)
			}
			if st.deficit >= chunk {
				st.deficit -= chunk
				st.left -= chunk
				served[st.demand.StreamID]++
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	return served
}
