package bbcr

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

const (
	MaxUnackedPerStream  uint64 = 256 * 1024
	MaxUnackedPerSession uint64 = 1024 * 1024
)

var ErrInvalidRetransmitRange = errors.New("bbcr: invalid retransmit range")

type RetransmitBuffer interface {
	AddBeforeWrite(ctx context.Context, start uint64, end uint64, frame []byte) error
	RetireThrough(ack uint64) (ACKEvent, error)
	MarkSACK(ranges []Range) error
	NextRTO(now time.Time) (Range, []byte, RTOEvent, bool)
	UnackedBytes() uint64
	SetEventSink(func(any))
}

type RetransmitSessionLimiter struct {
	mu     sync.Mutex
	cap    uint64
	used   uint64
	waitCh chan struct{}
}

func NewRetransmitSessionLimiter(cap uint64) *RetransmitSessionLimiter {
	if cap == 0 {
		cap = MaxUnackedPerSession
	}
	return &RetransmitSessionLimiter{cap: cap, waitCh: make(chan struct{})}
}

func (s *RetransmitSessionLimiter) tryReserve(n uint64) (bool, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used+n <= s.cap {
		s.used += n
		return true, s.waitCh
	}
	return false, s.waitCh
}

func (s *RetransmitSessionLimiter) release(n uint64) {
	s.mu.Lock()
	if n >= s.used {
		s.used = 0
	} else {
		s.used -= n
	}
	old := s.waitCh
	s.waitCh = make(chan struct{})
	close(old)
	s.mu.Unlock()
}

type RetransmitRing struct {
	mu                 sync.Mutex
	streamID           uint32
	direction          FrameFlags
	clock              Clock
	session            *RetransmitSessionLimiter
	entries            []rtxEntry
	ackOffset          uint64
	sentEnd            uint64
	unacked            uint64
	retransmittedBytes uint64
	started            time.Time
	waitCh             chan struct{}
	sink               func(any)
}

type rtxEntry struct {
	start   uint64
	end     uint64
	frame   []byte
	nextRTO time.Time
	attempt int
	sacked  bool
}

func NewRetransmitBuffer(streamID uint32, direction FrameFlags, clock Clock, session *RetransmitSessionLimiter) *RetransmitRing {
	if clock == nil {
		clock = RealClock{}
	}
	if session == nil {
		session = NewRetransmitSessionLimiter(MaxUnackedPerSession)
	}
	return &RetransmitRing{streamID: streamID, direction: direction, clock: clock, session: session, started: clock.Now(), waitCh: make(chan struct{})}
}

func (b *RetransmitRing) AddBeforeWrite(ctx context.Context, start uint64, end uint64, frame []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if end <= start || len(frame) == 0 {
		return ErrInvalidRetransmitRange
	}
	size := end - start
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.mu.Lock()
		streamOK := b.unacked+size <= MaxUnackedPerStream
		localWait := b.waitCh
		b.mu.Unlock()
		if streamOK {
			reserved, sessionWait := b.session.tryReserve(size)
			if reserved {
				b.mu.Lock()
				if b.unacked+size <= MaxUnackedPerStream && !b.overlapsLocked(start, end) {
					b.addLocked(start, end, frame)
					b.mu.Unlock()
					return nil
				}
				b.mu.Unlock()
				b.session.release(size)
				if b.overlaps(start, end) {
					return ErrInvalidRetransmitRange
				}
			} else {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-sessionWait:
				case <-localWait:
				}
				continue
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-localWait:
		}
	}
}

func (b *RetransmitRing) overlaps(start, end uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overlapsLocked(start, end)
}

func (b *RetransmitRing) overlapsLocked(start, end uint64) bool {
	for _, e := range b.entries {
		if start < e.end && end > e.start {
			return true
		}
	}
	return false
}

func (b *RetransmitRing) addLocked(start, end uint64, frame []byte) {
	cp := append([]byte(nil), frame...)
	e := rtxEntry{start: start, end: end, frame: cp, nextRTO: b.clock.Now().Add(initialRTO)}
	b.entries = append(b.entries, e)
	sort.Slice(b.entries, func(i, j int) bool { return b.entries[i].start < b.entries[j].start })
	b.unacked += end - start
	if end > b.sentEnd {
		b.sentEnd = end
	}
}

func (b *RetransmitRing) RetireThrough(ack uint64) (ACKEvent, error) {
	var sink func(any)
	var event ACKEvent
	b.mu.Lock()
	if ack > b.sentEnd {
		b.mu.Unlock()
		return ACKEvent{}, ackBeyondSentError(FrameACK, b.streamID)
	}
	if ack <= b.ackOffset {
		event = b.ackEventLocked(0)
		b.mu.Unlock()
		return event, nil
	}
	b.ackOffset = ack
	released := uint64(0)
	kept := b.entries[:0]
	for _, e := range b.entries {
		if e.end <= ack {
			released += e.end - e.start
			continue
		}
		if e.start < ack {
			released += ack - e.start
			e.start = ack
		}
		kept = append(kept, e)
	}
	b.entries = kept
	if released > b.unacked {
		released = b.unacked
	}
	b.unacked -= released
	if released > 0 {
		b.session.release(released)
		b.signalLocked()
	}
	event = b.ackEventLocked(released)
	sink = b.sink
	b.mu.Unlock()
	if sink != nil && released > 0 {
		sink(event)
	}
	return event, nil
}

func (b *RetransmitRing) MarkSACK(ranges []Range) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := validateSACKRanges(ranges, b.ackOffset, b.sentEnd); err != nil {
		return err
	}
	merged := mergeRanges(ranges)
	for i := range b.entries {
		b.entries[i].sacked = false
		for _, r := range merged {
			if b.entries[i].start >= r.Start && b.entries[i].end <= r.End {
				b.entries[i].sacked = true
				break
			}
		}
	}
	return nil
}

func (b *RetransmitRing) NextRTO(now time.Time) (Range, []byte, RTOEvent, bool) {
	b.mu.Lock()
	idx := -1
	for i := range b.entries {
		if now.Before(b.entries[i].nextRTO) {
			continue
		}
		if idx == -1 || (!b.entries[i].sacked && b.entries[idx].sacked) || (b.entries[i].sacked == b.entries[idx].sacked && b.entries[i].start < b.entries[idx].start) {
			idx = i
		}
	}
	if idx == -1 {
		b.mu.Unlock()
		return Range{}, nil, RTOEvent{}, false
	}
	e := &b.entries[idx]
	e.attempt++
	r := Range{Start: e.start, End: e.end}
	frame := append([]byte(nil), e.frame...)
	e.nextRTO = now.Add(rtoDelay(e.attempt + 1))
	bytes := e.end - e.start
	b.retransmittedBytes += bytes
	event := RTOEvent{StreamID: b.streamID, Range: r, Attempt: e.attempt, UnackedBytes: b.unacked, Time: now}
	sink := b.sink
	b.mu.Unlock()
	if sink != nil {
		sink(event)
	}
	return r, frame, event, true
}

func (b *RetransmitRing) UnackedBytes() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.unacked
}

func (b *RetransmitRing) SetEventSink(sink func(any)) {
	b.mu.Lock()
	b.sink = sink
	b.mu.Unlock()
}

func (b *RetransmitRing) RetransmitRate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	elapsed := b.clock.Now().Sub(b.started).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(b.retransmittedBytes*8) / elapsed
}

func (b *RetransmitRing) ackEventLocked(newly uint64) ACKEvent {
	return ACKEvent{StreamID: b.streamID, Direction: b.direction, AckOffset: b.ackOffset, NewlyAckedBytes: newly, UnackedBytes: b.unacked, Time: b.clock.Now()}
}

func (b *RetransmitRing) signalLocked() {
	old := b.waitCh
	b.waitCh = make(chan struct{})
	close(old)
}

const initialRTO = 750 * time.Millisecond

func rtoDelay(attempt int) time.Duration {
	switch {
	case attempt <= 1:
		return 750 * time.Millisecond
	case attempt == 2:
		return 1500 * time.Millisecond
	case attempt == 3:
		return 3 * time.Second
	default:
		return 5 * time.Second
	}
}
