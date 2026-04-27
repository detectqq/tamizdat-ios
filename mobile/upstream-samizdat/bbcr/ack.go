package bbcr

import (
	"sync"
	"time"
)

type ACKEvent struct {
	StreamID        uint32
	Direction       FrameFlags
	AckOffset       uint64
	NewlyAckedBytes uint64
	UnackedBytes    uint64
	Time            time.Time
}

type RTOEvent struct {
	StreamID     uint32
	Range        Range
	Attempt      int
	UnackedBytes uint64
	Time         time.Time
}

type ACKTracker interface {
	AckOffset() uint64
	ObserveACK(ack uint64) (ACKEvent, error)
	ObserveSACK(cumulative uint64, ranges []Range) error
	UnackedBytes() uint64
	RetransmitRate() float64
}

type PeerACKTracker struct {
	mu                 sync.Mutex
	streamID           uint32
	direction          FrameFlags
	clock              Clock
	ackOffset          uint64
	sentEnd            uint64
	retiredBytes       uint64
	retransmittedBytes uint64
	started            time.Time
	sack               []Range
}

func NewACKTracker(streamID uint32, direction FrameFlags, sentEnd uint64, clock Clock) *PeerACKTracker {
	if clock == nil {
		clock = RealClock{}
	}
	return &PeerACKTracker{streamID: streamID, direction: direction, clock: clock, sentEnd: sentEnd, started: clock.Now()}
}

func (t *PeerACKTracker) AckOffset() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ackOffset
}

func (t *PeerACKTracker) ObserveSent(start, end uint64) {
	if end <= start {
		return
	}
	t.mu.Lock()
	if end > t.sentEnd {
		t.sentEnd = end
	}
	t.mu.Unlock()
}

func (t *PeerACKTracker) SetFinalOffset(final uint64) {
	t.mu.Lock()
	if final+1 > t.sentEnd {
		t.sentEnd = final + 1
	}
	t.mu.Unlock()
}

func (t *PeerACKTracker) LocalWriteSucceeded(start, end uint64) {}

func (t *PeerACKTracker) ObserveACK(ack uint64) (ACKEvent, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.observeACKLocked(ack)
}

func (t *PeerACKTracker) observeACKLocked(ack uint64) (ACKEvent, error) {
	if ack > t.sentEnd {
		return ACKEvent{}, ackBeyondSentError(FrameACK, t.streamID)
	}
	if ack <= t.ackOffset {
		return ACKEvent{StreamID: t.streamID, Direction: t.direction, AckOffset: t.ackOffset, UnackedBytes: t.unackedLocked(), Time: t.clock.Now()}, nil
	}
	newly := ack - t.ackOffset
	t.ackOffset = ack
	t.retiredBytes += newly
	return ACKEvent{StreamID: t.streamID, Direction: t.direction, AckOffset: t.ackOffset, NewlyAckedBytes: newly, UnackedBytes: t.unackedLocked(), Time: t.clock.Now()}, nil
}

func (t *PeerACKTracker) ObserveSACK(cumulative uint64, ranges []Range) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cumulative > t.sentEnd {
		return ackBeyondSentError(FrameSACK, t.streamID)
	}
	if err := validateSACKRanges(ranges, cumulative, t.sentEnd); err != nil {
		return err
	}
	merged := mergeRanges(ranges)
	if cumulative > t.ackOffset {
		if _, err := t.observeACKLocked(cumulative); err != nil {
			return err
		}
	}
	t.sack = merged
	return nil
}

func (t *PeerACKTracker) UnackedBytes() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unackedLocked()
}

func (t *PeerACKTracker) unackedLocked() uint64 {
	if t.sentEnd <= t.ackOffset {
		return 0
	}
	return t.sentEnd - t.ackOffset
}

func (t *PeerACKTracker) RetransmitRate() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	elapsed := t.clock.Now().Sub(t.started).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(t.retransmittedBytes*8) / elapsed
}

func (t *PeerACKTracker) ObserveRetransmit(bytes uint64) {
	t.mu.Lock()
	t.retransmittedBytes += bytes
	t.mu.Unlock()
}

func (t *PeerACKTracker) RetiredBytes() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.retiredBytes
}

func (t *PeerACKTracker) SACKRanges() []Range {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Range(nil), t.sack...)
}

func ackBeyondSentError(ft FrameType, streamID uint32) error {
	return ProtocolError{Err: ErrACKBeyondSent, Code: ErrCodeACKBeyondSent, Tier: TierStreamRST, FrameType: ft, StreamID: streamID}
}

func validateSACKRanges(ranges []Range, cumulative uint64, sentEnd uint64) error {
	if len(ranges) > 32 {
		return payloadError(FrameSACK, 0)
	}
	var prevEnd uint64
	for i, r := range ranges {
		if r.End <= r.Start || r.Start < cumulative || r.End > sentEnd {
			return payloadError(FrameSACK, 0)
		}
		if i > 0 && r.Start < prevEnd {
			return payloadError(FrameSACK, 0)
		}
		prevEnd = r.End
	}
	return nil
}

func mergeRanges(ranges []Range) []Range {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]Range, 0, len(ranges))
	for _, r := range ranges {
		if len(out) == 0 || r.Start > out[len(out)-1].End {
			out = append(out, r)
			continue
		}
		if r.End > out[len(out)-1].End {
			out[len(out)-1].End = r.End
		}
	}
	return out
}
