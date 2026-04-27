package bbcr

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	// TransportIdle is an E1 compatibility state for an authenticated outer that
	// has opened BBCR CONNECT but has not yet flushed REBIND accept.
	TransportIdle TransportState = -1
	// TransportActive aliases the Phase-D open state without editing state.go.
	TransportActive TransportState = TransportOpen
)

var (
	ErrTransportNotActive = errors.New("bbcr: transport is not active")
	ErrTransportClosed    = errors.New("bbcr: transport closed")
)

type OuterTransportConfig struct {
	Epoch               uint32
	Clock               Clock
	RemainingPcapBudget uint64
	RetainSent          bool
	Send                func(context.Context, Frame) error
	Close               func(error) error
}

type OuterTransport struct {
	mu         sync.Mutex
	epoch      uint32
	state      TransportState
	clock      Clock
	remaining  uint64
	send       func(context.Context, Frame) error
	closeFn    func(error) error
	session    *Session
	sent       []Frame
	retainSent bool
	closed     bool
	timers     []Timer
}

func NewOuterTransport(cfg OuterTransportConfig) *OuterTransport {
	clk := cfg.Clock
	if clk == nil {
		clk = RealClock{}
	}
	remaining := cfg.RemainingPcapBudget
	if remaining == 0 {
		remaining = HardCapPcap - DefaultFixedS2CBudget
	}
	return &OuterTransport{epoch: cfg.Epoch, state: TransportIdle, clock: clk, remaining: remaining, send: cfg.Send, closeFn: cfg.Close, retainSent: cfg.RetainSent}
}

func (t *OuterTransport) Epoch() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.epoch
}

func (t *OuterTransport) State() TransportState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *OuterTransport) RemainingPcapBudget() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remaining
}

func (t *OuterTransport) SentFrames() []Frame {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Frame, len(t.sent))
	copy(out, t.sent)
	return out
}

func (t *OuterTransport) SendFrame(ctx context.Context, f Frame) error {
	return t.sendFrame(ctx, f, false)
}

func (t *OuterTransport) sendFrameDuringHandshake(ctx context.Context, f Frame) error {
	return t.sendFrame(ctx, f, true)
}

func (t *OuterTransport) sendFrame(ctx context.Context, f Frame, allowIdle bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	if t.closed || t.state == TransportClosed {
		t.mu.Unlock()
		return ErrTransportClosed
	}
	if t.state != TransportActive && !(allowIdle && t.state == TransportIdle) {
		t.mu.Unlock()
		return ErrTransportNotActive
	}
	wireBytes := FramePcapOverhead + uint64(len(f.Payload))
	if wireBytes >= t.remaining {
		t.remaining = 0
	} else {
		t.remaining -= wireBytes
	}
	if t.retainSent {
		t.sent = append(t.sent, cloneFrame(f))
	}
	send := t.send
	t.mu.Unlock()
	if send != nil {
		return send(ctx, f)
	}
	return nil
}

func (t *OuterTransport) Close(err error) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.state = TransportClosed
	for _, tm := range t.timers {
		if tm != nil {
			tm.Stop()
		}
	}
	t.timers = nil
	epoch := t.epoch
	s := t.session
	closeFn := t.closeFn
	t.mu.Unlock()
	if closeFn != nil {
		if cerr := closeFn(err); cerr != nil {
			return cerr
		}
	}
	if s != nil {
		s.onTransportClosed(epoch)
	}
	return nil
}

func (t *OuterTransport) MarkActive() {
	t.setState(TransportActive)
}

func (t *OuterTransport) MarkDraining() {
	t.setState(TransportDraining)
	t.mu.Lock()
	d := DefaultDrainTimeout
	if t.session != nil {
		d = t.session.drainTO
	}
	clk := t.clock
	t.mu.Unlock()
	tm := clk.AfterFunc(d, func() { _ = t.Close(nil) })
	t.mu.Lock()
	if !t.closed {
		t.timers = append(t.timers, tm)
	} else {
		tm.Stop()
	}
	t.mu.Unlock()
}

func (t *OuterTransport) ArmRebindTimeout(d time.Duration, f func()) {
	if d <= 0 {
		d = DefaultRebindTimeout
	}
	tm := t.clock.AfterFunc(d, func() {
		shouldClose := false
		t.mu.Lock()
		if !t.closed && t.state == TransportIdle {
			shouldClose = true
		}
		t.mu.Unlock()
		if shouldClose {
			_ = t.Close(ErrFirstFrameNotRebind)
		}
		if f != nil {
			f()
		}
	})
	t.mu.Lock()
	if !t.closed && t.state == TransportIdle {
		t.timers = append(t.timers, tm)
	} else {
		tm.Stop()
	}
	t.mu.Unlock()
}

func (t *OuterTransport) setEpoch(epoch uint32) {
	t.mu.Lock()
	t.epoch = epoch
	t.mu.Unlock()
}

func (t *OuterTransport) setSession(s *Session) {
	t.mu.Lock()
	t.session = s
	t.mu.Unlock()
}

func (t *OuterTransport) setState(st TransportState) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.state = st
	t.mu.Unlock()
}

func cloneFrame(f Frame) Frame {
	out := f
	if f.Payload != nil {
		out.Payload = append([]byte(nil), f.Payload...)
	}
	return out
}
