package bbcr

import (
	"errors"
	"expvar"
)

const DefaultReassemblyBufferSize uint64 = 32 * 1024

var (
	ErrReassemblyBufferFull        = errors.New("bbcr: reassembly buffer full")
	reassemblyBufferHighWaterBytes = expvar.NewInt("samizdat.bbcr.reassembly.buffer_high_water_bytes")
)

type Reassembler interface {
	// InsertData returns application bytes newly made contiguous. If this DATA
	// completes a previously received FIN, EOF is recorded internally and the
	// returned ACK advances to F+1; this pinned interface has no EOF boolean on
	// InsertData, so callers infer deferred EOF from ACK/AckState.
	InsertData(start uint64, payload []byte) (delivered [][]byte, ack uint64, sack []Range, err error)
	InsertFIN(offset uint64) (deliverEOF bool, ack uint64, err error)
	AckState() (ack uint64, sack []Range)
	BufferedBytes() uint64
}

type reassemblyRange struct {
	start uint64
	end   uint64
	data  []byte
}

type reassembler struct {
	readNext     uint64
	ranges       []reassemblyRange
	buffered     uint64
	limit        uint64
	finSet       bool
	finOffset    uint64
	deliveredFIN bool
}

func NewReassembler() Reassembler { return NewReassemblerWithLimit(DefaultReassemblyBufferSize) }

func NewReassemblerWithLimit(limit uint64) Reassembler { return &reassembler{limit: limit} }

func (r *reassembler) InsertData(start uint64, payload []byte) ([][]byte, uint64, []Range, error) {
	if len(payload) == 0 {
		ack, sack := r.AckState()
		return nil, ack, sack, reassemblyMalformed(FrameDATA)
	}
	end, ok := checkedEnd(start, uint64(len(payload)))
	if !ok {
		ack, sack := r.AckState()
		return nil, ack, sack, reassemblyMalformed(FrameDATA)
	}
	if r.finSet && end > r.finOffset {
		ack, sack := r.AckState()
		return nil, ack, sack, reassemblyProtocol(FrameDATA)
	}
	if end <= r.readNext {
		ack, sack := r.AckState()
		return nil, ack, sack, nil
	}
	if start == r.readNext && len(r.ranges) == 0 {
		r.readNext = end
		if r.finSet && !r.deliveredFIN && r.readNext == r.finOffset {
			r.deliveredFIN = true
			r.readNext++
		}
		ack, sack := r.AckState()
		return [][]byte{payload}, ack, sack, nil
	}

	frag := reassemblyRange{start: start, end: end, data: append([]byte(nil), payload...)}
	if frag.start < r.readNext {
		cut := r.readNext - frag.start
		frag.data = frag.data[int(cut):]
		frag.start = r.readNext
	}
	frags := trimFragments([]reassemblyRange{frag}, r.ranges)
	if len(frags) == 0 {
		ack, sack := r.AckState()
		return nil, ack, sack, nil
	}

	nextRanges := cloneRanges(r.ranges)
	for _, f := range frags {
		nextRanges = insertReassemblyRange(nextRanges, f)
	}
	readNext := r.readNext
	deliveredFIN := r.deliveredFIN
	delivered, drainedRanges, buffered := drainContiguous(nextRanges, readNext, r.finSet, r.finOffset, deliveredFIN)
	if buffered > r.limit {
		ack, sack := r.AckState()
		return nil, ack, sack, ProtocolError{Err: ErrReassemblyBufferFull, Code: ErrCodeStreamRSTProtocol, Tier: TierStreamRST, FrameType: FrameDATA}
	}

	r.ranges = drainedRanges
	r.buffered = buffered
	observeReassemblyBufferHighWater(buffered)
	for _, chunk := range delivered {
		r.readNext += uint64(len(chunk))
	}
	if r.finSet && !r.deliveredFIN && r.readNext == r.finOffset {
		r.deliveredFIN = true
		r.readNext++
	}
	ack, sack := r.AckState()
	return delivered, ack, sack, nil
}

func (r *reassembler) InsertFIN(offset uint64) (bool, uint64, error) {
	if r.finSet {
		if r.finOffset != offset {
			return false, r.readNext, reassemblyProtocol(FrameFIN)
		}
		return false, r.readNext, nil
	}
	if offset < r.readNext || r.hasBufferedAtOrAbove(offset) {
		return false, r.readNext, reassemblyProtocol(FrameFIN)
	}
	r.finSet = true
	r.finOffset = offset
	if r.readNext == offset {
		r.deliveredFIN = true
		r.readNext++
		return true, r.readNext, nil
	}
	return false, r.readNext, nil
}

func (r *reassembler) hasBufferedAtOrAbove(offset uint64) bool {
	for _, rg := range r.ranges {
		if rg.end > offset {
			return true
		}
	}
	return false
}

func (r *reassembler) AckState() (uint64, []Range) {
	return r.readNext, sackRanges(r.readNext, r.ranges)
}

func (r *reassembler) BufferedBytes() uint64 { return r.buffered }

func observeReassemblyBufferHighWater(buffered uint64) {
	if buffered > uint64(reassemblyBufferHighWaterBytes.Value()) {
		reassemblyBufferHighWaterBytes.Set(int64(buffered))
	}
}

func checkedEnd(start, length uint64) (uint64, bool) {
	end := start + length
	return end, end >= start
}

func cloneRanges(in []reassemblyRange) []reassemblyRange {
	out := make([]reassemblyRange, len(in))
	copy(out, in)
	return out
}

func trimFragments(frags []reassemblyRange, existing []reassemblyRange) []reassemblyRange {
	// existing is maintained sorted/non-overlapping by insertReassemblyRange and
	// mergeAdjacentRanges. That invariant makes the frags[:0] rewrite safe while
	// progressively carving duplicate bytes out of at most the rightmost fragment.
	for _, ex := range existing {
		next := frags[:0]
		for _, f := range frags {
			if f.end <= ex.start || f.start >= ex.end {
				next = append(next, f)
				continue
			}
			if f.start < ex.start {
				leftLen := ex.start - f.start
				next = append(next, reassemblyRange{start: f.start, end: ex.start, data: append([]byte(nil), f.data[:int(leftLen)]...)})
			}
			if ex.end < f.end {
				cut := ex.end - f.start
				next = append(next, reassemblyRange{start: ex.end, end: f.end, data: append([]byte(nil), f.data[int(cut):]...)})
			}
		}
		frags = next
		if len(frags) == 0 {
			break
		}
	}
	return frags
}

func insertReassemblyRange(ranges []reassemblyRange, rg reassemblyRange) []reassemblyRange {
	if rg.end <= rg.start {
		return ranges
	}
	rg.data = append([]byte(nil), rg.data...)
	idx := 0
	for idx < len(ranges) && ranges[idx].start < rg.start {
		idx++
	}
	ranges = append(ranges, reassemblyRange{})
	copy(ranges[idx+1:], ranges[idx:])
	ranges[idx] = rg
	return mergeAdjacentRanges(ranges)
}

func mergeAdjacentRanges(ranges []reassemblyRange) []reassemblyRange {
	if len(ranges) < 2 {
		return ranges
	}
	out := ranges[:0]
	for _, rg := range ranges {
		if len(out) == 0 {
			out = append(out, rg)
			continue
		}
		last := &out[len(out)-1]
		if last.end == rg.start {
			last.end = rg.end
			last.data = append(last.data, rg.data...)
			continue
		}
		out = append(out, rg)
	}
	return out
}

func drainContiguous(ranges []reassemblyRange, readNext uint64, finSet bool, finOffset uint64, deliveredFIN bool) ([][]byte, []reassemblyRange, uint64) {
	var delivered [][]byte
	for len(ranges) > 0 {
		first := ranges[0]
		if first.end <= readNext {
			ranges = ranges[1:]
			continue
		}
		if first.start < readNext {
			cut := readNext - first.start
			first.start = readNext
			first.data = first.data[int(cut):]
			ranges[0] = first
		}
		if first.start != readNext {
			break
		}
		delivered = append(delivered, append([]byte(nil), first.data...))
		readNext = first.end
		ranges = ranges[1:]
		if finSet && !deliveredFIN && readNext == finOffset {
			deliveredFIN = true
			break
		}
	}
	return delivered, ranges, countBuffered(ranges)
}

func countBuffered(ranges []reassemblyRange) uint64 {
	var total uint64
	for _, rg := range ranges {
		total += rg.end - rg.start
	}
	return total
}

func sackRanges(ack uint64, ranges []reassemblyRange) []Range {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]Range, 0, len(ranges))
	for _, rg := range ranges {
		if rg.end <= ack {
			continue
		}
		start := rg.start
		if start < ack {
			start = ack
		}
		out = append(out, Range{Start: start, End: rg.end})
		if len(out) == 32 {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func reassemblyMalformed(ft FrameType) error {
	return ProtocolError{Err: ErrMalformedPayload, Code: ErrCodeMalformedPayload, Tier: TierStreamRST, FrameType: ft}
}

func reassemblyProtocol(ft FrameType) error {
	return ProtocolError{Err: ErrStreamRSTProtocol, Code: ErrCodeStreamRSTProtocol, Tier: TierStreamRST, FrameType: ft}
}
