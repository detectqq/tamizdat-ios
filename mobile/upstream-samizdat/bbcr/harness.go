package bbcr

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"time"
)

var (
	ErrHarnessClosed      = errors.New("bbcr harness: closed")
	ErrInvalidChaosConfig = errors.New("bbcr harness: invalid chaos config")
	ErrGoroutineLeak      = errors.New("bbcr harness: goroutine leak")
)

const DefaultChaosSeed int64 = 1

type Direction uint8

const (
	DirectionC2S Direction = iota
	DirectionS2C
)

func (d Direction) String() string {
	switch d {
	case DirectionC2S:
		return "client-to-server"
	case DirectionS2C:
		return "server-to-client"
	default:
		return fmt.Sprintf("direction-%d", uint8(d))
	}
}

type FreezeWriteResult struct {
	Accepted  int
	Delivered int
	Dropped   int
	Frozen    bool
}

type FreezeSimulator interface {
	Write(Direction, []byte) (FreezeWriteResult, error)
	Delivered(Direction) []byte
	DroppedBytes(Direction) uint64
	FreezeAfter() uint64
	Reset()
	Close() error
}

type ByteFreezeSimulator struct {
	mu          sync.Mutex
	freezeAfter uint64
	s2cSeen     uint64
	delivered   map[Direction][]byte
	dropped     map[Direction]uint64
	closed      bool
}

func NewFreezeSimulator(freezeAfter uint64) *ByteFreezeSimulator {
	return &ByteFreezeSimulator{
		freezeAfter: freezeAfter,
		delivered:   map[Direction][]byte{DirectionC2S: nil, DirectionS2C: nil},
		dropped:     map[Direction]uint64{DirectionC2S: 0, DirectionS2C: 0},
	}
}

func (s *ByteFreezeSimulator) FreezeAfter() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.freezeAfter
}

func (s *ByteFreezeSimulator) Write(dir Direction, p []byte) (FreezeWriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return FreezeWriteResult{}, ErrHarnessClosed
	}
	res := FreezeWriteResult{Accepted: len(p), Delivered: len(p)}
	if dir != DirectionS2C {
		s.delivered[dir] = append(s.delivered[dir], p...)
		return res, nil
	}
	remaining := uint64(0)
	if s.s2cSeen < s.freezeAfter {
		remaining = s.freezeAfter - s.s2cSeen
	}
	deliver := len(p)
	if uint64(deliver) > remaining {
		deliver = int(remaining)
	}
	if deliver > 0 {
		s.delivered[dir] = append(s.delivered[dir], p[:deliver]...)
	}
	dropped := len(p) - deliver
	if dropped > 0 {
		s.dropped[dir] += uint64(dropped)
		res.Frozen = true
	}
	s.s2cSeen = saturatingAdd(s.s2cSeen, uint64(len(p)))
	res.Delivered = deliver
	res.Dropped = dropped
	return res, nil
}

func (s *ByteFreezeSimulator) Delivered(dir Direction) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.delivered[dir]...)
}

func (s *ByteFreezeSimulator) DroppedBytes(dir Direction) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped[dir]
}

func (s *ByteFreezeSimulator) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.s2cSeen = 0
	for k := range s.delivered {
		s.delivered[k] = nil
	}
	for k := range s.dropped {
		s.dropped[k] = 0
	}
	s.closed = false
}

func (s *ByteFreezeSimulator) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type FrameEnvelope struct {
	Direction Direction
	Frame     Frame
}

type ChaosConfig struct {
	Seed                 int64
	DropProbability      float64
	DuplicateProbability float64
	ReorderWindow        int
}

type ChaosController interface {
	Seed() int64
	Description() string
	Apply([]FrameEnvelope) []FrameEnvelope
}

type deterministicChaosController struct {
	cfg ChaosConfig
}

func NewChaosController(cfg ChaosConfig) (ChaosController, error) {
	if cfg.Seed == 0 {
		cfg.Seed = DefaultChaosSeed
	}
	if cfg.DropProbability < 0 || cfg.DropProbability > 1 || math.IsNaN(cfg.DropProbability) || cfg.DuplicateProbability < 0 || cfg.DuplicateProbability > 1 || math.IsNaN(cfg.DuplicateProbability) || cfg.ReorderWindow < 0 {
		return nil, ErrInvalidChaosConfig
	}
	return &deterministicChaosController{cfg: cfg}, nil
}

func (c *deterministicChaosController) Seed() int64 { return c.cfg.Seed }

func (c *deterministicChaosController) Description() string {
	return fmt.Sprintf("seed=%d drop=%.3f duplicate=%.3f reorder_window=%d", c.cfg.Seed, c.cfg.DropProbability, c.cfg.DuplicateProbability, c.cfg.ReorderWindow)
}

func (c *deterministicChaosController) Apply(in []FrameEnvelope) []FrameEnvelope {
	rng := rand.New(rand.NewSource(c.cfg.Seed))
	out := make([]FrameEnvelope, 0, len(in))
	for _, env := range in {
		if c.cfg.DropProbability > 0 && rng.Float64() < c.cfg.DropProbability {
			continue
		}
		cloned := cloneEnvelope(env)
		out = append(out, cloned)
		if c.cfg.DuplicateProbability > 0 && rng.Float64() < c.cfg.DuplicateProbability {
			out = append(out, cloneEnvelope(env))
		}
	}
	if c.cfg.ReorderWindow > 1 {
		for start := 0; start < len(out); start += c.cfg.ReorderWindow {
			end := start + c.cfg.ReorderWindow
			if end > len(out) {
				end = len(out)
			}
			rng.Shuffle(end-start, func(i, j int) { out[start+i], out[start+j] = out[start+j], out[start+i] })
		}
	}
	return out
}

func cloneEnvelope(env FrameEnvelope) FrameEnvelope {
	return FrameEnvelope{Direction: env.Direction, Frame: cloneFrame(env.Frame)}
}

type HarnessDialLimiter struct {
	gate DialGate
	key  DialKey
}

func NewHarnessDialLimiter(gate DialGate, key DialKey) *HarnessDialLimiter {
	return &HarnessDialLimiter{gate: gate, key: key}
}

func (l *HarnessDialLimiter) TryAcquire(now time.Time) bool {
	if l == nil || l.gate == nil {
		return false
	}
	return l.gate.TryAcquire(l.key, now)
}

func (l *HarnessDialLimiter) Wait(ctx context.Context) error {
	if l == nil || l.gate == nil {
		return ErrInvalidDialKey
	}
	return l.gate.Wait(ctx, l.key)
}

func (l *HarnessDialLimiter) Snapshot(now time.Time) (float64, time.Time) {
	if l == nil || l.gate == nil {
		return 0, time.Time{}
	}
	return l.gate.Snapshot(l.key, now)
}

type GoroutineLeakResult struct {
	Baseline int
	Current  int
	Delta    int
	MaxDelta int
}

type RuntimeGoroutineLeakHarness struct {
	mu       sync.Mutex
	counter  func() int
	baseline int
	started  bool
	maxDelta int
}

func NewGoroutineLeakHarness(maxDelta int) *RuntimeGoroutineLeakHarness {
	return NewGoroutineLeakHarnessWithCounter(maxDelta, runtime.NumGoroutine)
}

func NewGoroutineLeakHarnessWithCounter(maxDelta int, counter func() int) *RuntimeGoroutineLeakHarness {
	if maxDelta < 0 {
		maxDelta = 0
	}
	if counter == nil {
		counter = runtime.NumGoroutine
	}
	return &RuntimeGoroutineLeakHarness{counter: counter, maxDelta: maxDelta}
}

func (h *RuntimeGoroutineLeakHarness) Start() GoroutineLeakResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.baseline = h.counter()
	h.started = true
	return GoroutineLeakResult{Baseline: h.baseline, Current: h.baseline, Delta: 0, MaxDelta: h.maxDelta}
}

func (h *RuntimeGoroutineLeakHarness) Check() (GoroutineLeakResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.started {
		h.baseline = h.counter()
		h.started = true
	}
	cur := h.counter()
	res := GoroutineLeakResult{Baseline: h.baseline, Current: cur, Delta: cur - h.baseline, MaxDelta: h.maxDelta}
	if res.Delta > h.maxDelta {
		return res, fmt.Errorf("%w: baseline=%d current=%d delta=%d max=%d", ErrGoroutineLeak, res.Baseline, res.Current, res.Delta, res.MaxDelta)
	}
	return res, nil
}

type ManualClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  map[*manualTimer]struct{}
	tickers map[*manualTicker]struct{}
}

func NewManualClock(start time.Time) *ManualClock {
	if start.IsZero() {
		start = time.Unix(0, 0)
	}
	return &ManualClock{now: start, timers: make(map[*manualTimer]struct{}), tickers: make(map[*manualTicker]struct{})}
}

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *ManualClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	if d < 0 {
		d = 0
	}
	c.mu.Lock()
	deadline := c.now.Add(d)
	t := &manualTimer{clock: c, deadline: deadline, active: true}
	t.f = func() { ch <- deadline; close(ch) }
	c.timers[t] = struct{}{}
	c.mu.Unlock()
	return ch
}

func (c *ManualClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d < 0 {
		d = 0
	}
	t := &manualTimer{clock: c, deadline: c.now.Add(d), f: f, active: true}
	c.timers[t] = struct{}{}
	return t
}

func (c *ManualClock) NewTicker(d time.Duration) Ticker {
	if d <= 0 {
		d = time.Nanosecond
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &manualTicker{clock: c, interval: d, next: c.now.Add(d), ch: make(chan time.Time, 64), active: true}
	c.tickers[t] = struct{}{}
	return t
}

func (c *ManualClock) Advance(d time.Duration) {
	if d < 0 {
		return
	}
	var timerCalls []func()
	var tickerSends []struct {
		ch chan time.Time
		at time.Time
	}
	c.mu.Lock()
	end := c.now.Add(d)
	for {
		var next time.Time
		for tm := range c.timers {
			if tm.active && (next.IsZero() || tm.deadline.Before(next)) {
				next = tm.deadline
			}
		}
		for tk := range c.tickers {
			if tk.active && (next.IsZero() || tk.next.Before(next)) {
				next = tk.next
			}
		}
		if next.IsZero() || next.After(end) {
			break
		}
		c.now = next
		var dueTimers []*manualTimer
		for tm := range c.timers {
			if tm.active && !tm.deadline.After(c.now) {
				dueTimers = append(dueTimers, tm)
			}
		}
		sort.Slice(dueTimers, func(i, j int) bool { return dueTimers[i].deadline.Before(dueTimers[j].deadline) })
		for _, tm := range dueTimers {
			if tm.active {
				tm.active = false
				delete(c.timers, tm)
				if tm.f != nil {
					timerCalls = append(timerCalls, tm.f)
				}
			}
		}
		for tk := range c.tickers {
			for tk.active && !tk.next.After(c.now) {
				tickerSends = append(tickerSends, struct {
					ch chan time.Time
					at time.Time
				}{tk.ch, tk.next})
				tk.next = tk.next.Add(tk.interval)
			}
		}
	}
	c.now = end
	c.mu.Unlock()
	for _, send := range tickerSends {
		select {
		case send.ch <- send.at:
		default:
		}
	}
	for _, call := range timerCalls {
		call()
	}
}

type manualTimer struct {
	clock    *ManualClock
	deadline time.Time
	f        func()
	active   bool
}

func (t *manualTimer) Stop() bool {
	if t == nil || t.clock == nil {
		return false
	}
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.active = false
	delete(t.clock.timers, t)
	return was
}

func (t *manualTimer) Reset(d time.Duration) bool {
	if t == nil || t.clock == nil {
		return false
	}
	if d < 0 {
		d = 0
	}
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.deadline = t.clock.now.Add(d)
	t.active = true
	t.clock.timers[t] = struct{}{}
	return was
}

type manualTicker struct {
	clock    *ManualClock
	interval time.Duration
	next     time.Time
	ch       chan time.Time
	active   bool
}

func (t *manualTicker) C() <-chan time.Time { return t.ch }

func (t *manualTicker) Stop() {
	if t == nil || t.clock == nil {
		return
	}
	t.clock.mu.Lock()
	t.active = false
	delete(t.clock.tickers, t)
	t.clock.mu.Unlock()
}
