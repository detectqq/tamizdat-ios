package bbcr

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// DefaultInitialStreamWindow is the default per-stream receive credit
	// when StreamConfig.RecvWindow is unset.
	DefaultInitialStreamWindow uint64 = 256 * 1024
	// InitialStreamWindow is retained as a compatibility alias for
	// existing call-sites/tests; it is identical to the default.
	InitialStreamWindow = DefaultInitialStreamWindow
	// streamWindowUpdateThreshold remains defined for any external reference,
	// but Stream now derives its own threshold from recvWindow/4.
	streamWindowUpdateThreshold  = InitialStreamWindow / 4
	streamWindowUpdateIdleDelay  = 10 * time.Millisecond
	streamAckCoalesceFrames      = 16
	streamAckCoalesceIdleDelay   = 50 * time.Millisecond
	streamRetransmitPollInterval = 100 * time.Millisecond
	freshOuterRetransmitWait     = 50 * time.Millisecond
)

var streamRecvWindowWarningOnce sync.Once

var warnLogger = func(string, ...any) {}

var ErrStreamDeadlineExceeded = errors.New("bbcr: stream deadline exceeded")

type BBCRStream interface {
	net.Conn
	CloseWrite() error
	StreamID() uint32
}

type Transport interface {
	Epoch() uint32
	State() TransportState
	RemainingPcapBudget() uint64
	SendFrame(context.Context, Frame) error
	Close(error) error
}

type StreamConfig struct {
	StreamID      uint32
	SessionID     uint64
	Direction     FrameFlags
	Clock         Clock
	Transport     Transport
	Scheduler     *Scheduler
	Retransmit    RetransmitBuffer
	ACKTracker    ACKTracker
	Reassembler   Reassembler
	LocalAddr     net.Addr
	RemoteAddr    net.Addr
	SendWindowEnd uint64
	// RecvWindow, when non-zero, overrides the default initial receive
	// window for this stream. When zero, DefaultInitialStreamWindow is
	// used. Must be >= 16 KiB (the minimum window-update threshold floor).
	RecvWindow           uint64
	EnableRetransmitLoop bool
	EventSink            func(any)
}

type StreamWindowUpdateEvent struct {
	StreamID        uint32
	WindowEndOffset uint64
	BufferedBytes   uint64
	Time            time.Time
}

type StreamRSTEvent struct {
	StreamID uint32
	Payload  RSTPayload
	Err      error
	Time     time.Time
}

type Stream struct {
	mu    sync.Mutex
	cond  *sync.Cond
	wuMu  sync.Mutex
	ackMu sync.Mutex

	id         uint32
	sessionID  uint64
	direction  FrameFlags
	clock      Clock
	tr         Transport
	sched      *Scheduler
	rtx        RetransmitBuffer
	ack        ACKTracker
	reasm      Reassembler
	sink       func(any)
	localAddr  net.Addr
	remoteAddr net.Addr

	state           StreamState
	sendNext        uint64
	sendWindowEnd   uint64
	recvWindow      uint64
	localFINOffset  uint64
	localFINSent    bool
	localFINAcked   bool
	remoteEOF       bool
	remoteFINSet    bool
	remoteFINOffset uint64
	closed          bool
	resetErr        error

	readBuf       []byte
	readBufStart  int
	readDeadline  time.Time
	writeDeadline time.Time
	readExpired   bool
	writeExpired  bool
	readTimer     Timer
	writeTimer    Timer
	ctx           context.Context
	cancel        context.CancelFunc
	outboundWUs   chan Frame
	lastWUOffset  uint64
	wuIdleTimer   Timer

	ackCoalesce     int
	ackPending      bool
	ackPendingOff   uint64
	ackPendingSACK  []Range
	ackCoalesceIdle Timer
}

type streamAddr string

func (a streamAddr) Network() string { return "bbcr" }
func (a streamAddr) String() string  { return string(a) }

func NewStream(cfg StreamConfig) (*Stream, error) {
	if cfg.StreamID == 0 {
		return nil, streamStateProtocolError(0, FrameOPENSTREAM, "stream id must be nonzero")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = RealClock{}
	}
	reasm := cfg.Reassembler
	if reasm == nil {
		reasm = NewReassembler()
	}
	rtx := cfg.Retransmit
	if rtx == nil {
		rtx = NewRetransmitBuffer(cfg.StreamID, cfg.Direction, clk, nil)
	}
	if cfg.ACKTracker == nil {
		cfg.ACKTracker = NewACKTracker(cfg.StreamID, cfg.Direction, 0, clk)
	}
	if cfg.Scheduler != nil {
		if sinker, ok := rtx.(interface{ SetEventSink(func(any)) }); ok {
			scheduler := cfg.Scheduler
			sinker.SetEventSink(func(ev any) {
				if rto, ok := ev.(RTOEvent); ok {
					scheduler.ObserveRTO(rto)
				}
			})
		}
	}
	recvWindow := cfg.RecvWindow
	if recvWindow == 0 {
		recvWindow = DefaultInitialStreamWindow
	} else if recvWindow < 16*1024 {
		streamRecvWindowWarningOnce.Do(func() {
			warnLogger("bbcr: StreamConfig.RecvWindow below 16 KiB; using DefaultInitialStreamWindow")
		})
		recvWindow = DefaultInitialStreamWindow
	}
	if cfg.SendWindowEnd == 0 {
		cfg.SendWindowEnd = recvWindow
	}
	local := cfg.LocalAddr
	if local == nil {
		local = streamAddr("bbcr-local")
	}
	remote := cfg.RemoteAddr
	if remote == nil {
		remote = streamAddr("bbcr-remote")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Stream{id: cfg.StreamID, sessionID: cfg.SessionID, direction: cfg.Direction, clock: clk, tr: cfg.Transport, sched: cfg.Scheduler, rtx: rtx, ack: cfg.ACKTracker, reasm: reasm, sink: cfg.EventSink, localAddr: local, remoteAddr: remote, state: StreamStateOpen, sendWindowEnd: cfg.SendWindowEnd, recvWindow: recvWindow, ctx: ctx, cancel: cancel}
	s.cond = sync.NewCond(&s.mu)
	if s.tr != nil || s.sched != nil {
		s.outboundWUs = make(chan Frame, 4)
		go s.windowUpdateWriter(s.outboundWUs)
		if cfg.EnableRetransmitLoop {
			go s.retransmitLoop()
		}
	}
	return s, nil
}

func (s *Stream) windowUpdateWriter(ch <-chan Frame) {
	for f := range ch {
		_ = s.sendFrame(context.Background(), f, FrameClassControl)
	}
}

func (s *Stream) retransmitLoop() {
	ticker := s.clock.NewTicker(streamRetransmitPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C():
			s.retransmitDue()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Stream) retransmitDue() bool {
	if s.rtx == nil {
		return false
	}
	_, wire, ev, ok := s.rtx.NextRTO(s.clock.Now())
	if !ok {
		return false
	}
	f, _, err := ParseFrame(wire, DecodeOptions{})
	if err != nil {
		return false
	}
	f.Header.Flags |= FlagRetransmit
	sent := false
	if s.sched != nil {
		s.sched.ObserveRTO(ev)
		_, err = s.sched.AssignFrame(context.Background(), f, ScheduleOptions{Class: FrameClassRetransmit, AvoidEpoch: f.Header.TransportEpoch})
		sent = err == nil
	} else if s.tr != nil {
		sent = s.tr.SendFrame(context.Background(), f) == nil
	}
	if sent {
		if obs, ok := s.ack.(interface{ ObserveRetransmit(uint64) }); ok {
			obs.ObserveRetransmit(ev.Range.End - ev.Range.Start)
		}
	}
	return sent
}

func (s *Stream) closeOutboundWUs() {
	s.wuMu.Lock()
	ch := s.outboundWUs
	s.outboundWUs = nil
	s.wuMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (s *Stream) StreamID() uint32   { return s.id }
func (s *Stream) State() StreamState { s.mu.Lock(); defer s.mu.Unlock(); return s.state }
func (s *Stream) UnackedBytes() uint64 {
	if s.rtx == nil {
		return 0
	}
	return s.rtx.UnackedBytes()
}
func (s *Stream) windowUpdateThreshold() uint64 {
	t := s.recvWindow / 4
	if t < 16*1024 {
		return 16 * 1024
	}
	return t
}
func (s *Stream) LocalAddr() net.Addr  { return s.localAddr }
func (s *Stream) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.readableBytesLocked() == 0 && !s.remoteEOF && !s.closed && s.resetErr == nil && !s.readExpired {
		s.cond.Wait()
	}
	if s.readableBytesLocked() > 0 {
		n := copy(p, s.readBuf[s.readBufStart:])
		s.readBufStart += n
		if s.readBufStart == len(s.readBuf) {
			s.resetReadBufferLocked()
		}
		return n, nil
	}
	if s.resetErr != nil {
		return 0, s.resetErr
	}
	if s.readExpired {
		return 0, ErrStreamDeadlineExceeded
	}
	if s.remoteEOF {
		return 0, io.EOF
	}
	return 0, net.ErrClosed
}

func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		n, err := s.writeChunk(p[written:])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (s *Stream) writeChunk(p []byte) (int, error) {
	s.mu.Lock()
	if err := s.waitWritableLocked(); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	avail := s.sendWindowEnd - s.sendNext
	if avail == 0 {
		s.mu.Unlock()
		return 0, ErrStreamDeadlineExceeded
	}
	n := len(p)
	if uint64(n) > avail {
		n = int(avail)
	}
	if n > int(MaxDataPayload) {
		n = int(MaxDataPayload)
	}
	start := s.sendNext
	end := start + uint64(n)
	payload := append([]byte(nil), p[:n]...)
	frame := s.newFrameLocked(FrameDATA, start, payload)
	wire, err := MarshalFrame(frame.Header, frame.Payload)
	deadline := s.writeDeadline
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	ctx, cancel := s.contextForDeadline(deadline)
	defer cancel()
	if err := s.rtx.AddBeforeWrite(ctx, start, end, wire); err != nil {
		return 0, s.mapWriteError(err)
	}
	if err := s.sendFrame(ctx, frame, FrameClassFreshData); err != nil {
		return 0, err
	}
	s.mu.Lock()
	if obs, ok := s.ack.(interface{ ObserveSent(uint64, uint64) }); ok {
		obs.ObserveSent(start, end)
	}
	s.sendNext = end
	s.mu.Unlock()
	return n, nil
}

func (s *Stream) waitWritableLocked() error {
	for {
		if s.resetErr != nil {
			return s.resetErr
		}
		if s.closed || s.localFINSent || s.state == StreamStateClosed || s.state == StreamStateReset {
			return net.ErrClosed
		}
		if s.writeExpired {
			return ErrStreamDeadlineExceeded
		}
		if s.sendNext < s.sendWindowEnd {
			return nil
		}
		s.cond.Wait()
	}
}

func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.localFINSent {
		s.mu.Unlock()
		return nil
	}
	if s.resetErr != nil || s.closed || s.state == StreamStateClosed || s.state == StreamStateReset {
		s.mu.Unlock()
		return net.ErrClosed
	}
	start := s.sendNext
	end := start + 1
	frame := s.newFrameLocked(FrameFIN, start, nil)
	wire, err := MarshalFrame(frame.Header, nil)
	deadline := s.writeDeadline
	s.localFINSent = true
	s.localFINOffset = start
	_ = s.applyLocked(StreamEventLocalFIN, FrameFIN)
	s.sendNext = end
	s.cond.Broadcast()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	ctx, cancel := s.contextForDeadline(deadline)
	defer cancel()
	if err := s.rtx.AddBeforeWrite(ctx, start, end, wire); err != nil {
		return s.mapWriteError(err)
	}
	if obs, ok := s.ack.(interface{ ObserveSent(uint64, uint64) }); ok {
		obs.ObserveSent(start, end)
	}
	if setter, ok := s.ack.(interface{ SetFinalOffset(uint64) }); ok {
		setter.SetFinalOffset(start)
	}
	return s.sendFrame(ctx, frame, FrameClassControl)
}

func (s *Stream) Close() error {
	_ = s.CloseWrite()
	s.forceFlushAck()
	s.forceFlushWindowUpdate()
	s.mu.Lock()
	if s.state != StreamStateReset {
		s.state = StreamStateClosed
	}
	s.closed = true
	s.cancel()
	s.resetReadBufferLocked()
	s.stopTimersLocked()
	s.cond.Broadcast()
	s.mu.Unlock()
	s.stopAckCoalesceIdleTimer()
	s.closeOutboundWUs()
	return nil
}

func (s *Stream) ReceiveData(start uint64, payload []byte) error {
	s.mu.Lock()
	delivered, ack, sack, err := s.reasm.InsertData(start, payload)
	if err != nil {
		s.mu.Unlock()
		_ = s.sendRST(RSTPayload{ErrorCode: 1})
		return err
	}
	if s.readBufStart == len(s.readBuf) {
		s.resetReadBufferLocked()
	}
	for _, chunk := range delivered {
		s.readBuf = append(s.readBuf, chunk...)
	}
	forceWindowUpdate := s.remoteFINSet && ack == s.remoteFINOffset+1
	if forceWindowUpdate && !s.remoteEOF {
		s.remoteEOF = true
		_ = s.applyLocked(StreamEventRemoteFIN, FrameFIN)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	if err := s.maybeSendAck(ack, sack, len(sack) > 0); err != nil {
		return err
	}
	s.maybeEmitWindowUpdate(ack, forceWindowUpdate)
	return nil
}

func (s *Stream) ReceiveFIN(offset uint64) error {
	s.mu.Lock()
	deliverEOF, ack, err := s.reasm.InsertFIN(offset)
	if err != nil {
		s.mu.Unlock()
		_ = s.sendRST(RSTPayload{ErrorCode: 1})
		return err
	}
	s.remoteFINSet = true
	s.remoteFINOffset = offset
	if deliverEOF {
		s.remoteEOF = true
		_ = s.applyLocked(StreamEventRemoteFIN, FrameFIN)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	if err := s.sendAckNow(ack, nil); err != nil {
		return err
	}
	s.maybeEmitWindowUpdate(ack, true)
	return nil
}

func (s *Stream) ReceiveRST(payload RSTPayload) error {
	err := net.ErrClosed
	s.mu.Lock()
	s.resetErr = err
	s.state = StreamStateReset
	s.cancel()
	s.resetReadBufferLocked()
	s.cond.Broadcast()
	s.mu.Unlock()
	s.stopAckCoalesceIdleTimer()
	s.stopWindowUpdateIdleTimer()
	if s.sink != nil {
		s.sink(StreamRSTEvent{StreamID: s.id, Payload: payload, Err: err, Time: s.clock.Now()})
	}
	return nil
}

func (s *Stream) HandleACK(ack uint64) error {
	if s.ack != nil {
		if _, err := s.ack.ObserveACK(ack); err != nil {
			return err
		}
	}
	if s.rtx != nil {
		ev, err := s.rtx.RetireThrough(ack)
		if err != nil {
			return err
		}
		if s.sched != nil {
			s.sched.ObserveACK(ev)
		}
	}
	s.mu.Lock()
	if s.localFINSent && ack >= s.localFINOffset+1 {
		s.localFINAcked = true
	}
	if s.localFINAcked && s.remoteEOF {
		s.state = StreamStateClosed
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}

func (s *Stream) HandleSACK(cumulative uint64, ranges []Range) error {
	if s.ack != nil {
		if err := s.ack.ObserveSACK(cumulative, ranges); err != nil {
			return err
		}
	}
	if err := s.rtx.MarkSACK(ranges); err != nil {
		return err
	}
	if s.rtx != nil {
		ev, err := s.rtx.RetireThrough(cumulative)
		if err != nil {
			return err
		}
		if s.sched != nil {
			s.sched.ObserveACK(ev)
		}
	}
	return nil
}

func (s *Stream) HandleWindowUpdate(end uint64) error {
	s.mu.Lock()
	if end > s.sendWindowEnd {
		s.sendWindowEnd = end
		s.cond.Broadcast()
	}
	s.mu.Unlock()
	return nil
}

func (s *Stream) SetSendWindowEnd(end uint64) {
	s.mu.Lock()
	s.sendWindowEnd = end
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setDeadlineLocked(true, t)
	return nil
}
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setDeadlineLocked(false, t)
	return nil
}

func (s *Stream) setDeadlineLocked(read bool, t time.Time) {
	if read {
		if s.readTimer != nil {
			s.readTimer.Stop()
			s.readTimer = nil
		}
		s.readDeadline = t
		s.readExpired = false
	} else {
		if s.writeTimer != nil {
			s.writeTimer.Stop()
			s.writeTimer = nil
		}
		s.writeDeadline = t
		s.writeExpired = false
	}
	if t.IsZero() {
		s.cond.Broadcast()
		return
	}
	d := t.Sub(s.clock.Now())
	if d <= 0 {
		if read {
			s.readExpired = true
		} else {
			s.writeExpired = true
		}
		s.cond.Broadcast()
		return
	}
	tm := s.clock.AfterFunc(d, func() {
		s.mu.Lock()
		if read {
			s.readExpired = true
		} else {
			s.writeExpired = true
		}
		s.cond.Broadcast()
		s.mu.Unlock()
	})
	if read {
		s.readTimer = tm
	} else {
		s.writeTimer = tm
	}
}

func (s *Stream) newFrameLocked(ft FrameType, seq uint64, payload []byte) Frame {
	ack, _ := s.reasm.AckState()
	return Frame{Header: FrameHeader{Version: Version1, Type: ft, Flags: s.direction, HeaderLen: HeaderLenV1, SessionID: s.sessionID, TransportEpoch: s.epoch(), StreamID: s.id, SeqOffset: seq, AckOffset: ack}, Payload: payload}
}

func (s *Stream) epoch() uint32 {
	if s.tr == nil {
		return 0
	}
	return s.tr.Epoch()
}

func (s *Stream) drainRetransmitsBeforeFreshData(ctx context.Context) {
	if s.sched == nil || !s.sched.FreshOuterPending() {
		return
	}
	if s.retransmitDue() || !s.sched.FreshOuterPending() {
		return
	}
	waitCtx, cancel := s.contextForWaitDeadline(ctx, freshOuterRetransmitWait)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for s.sched.FreshOuterPending() {
		select {
		case <-waitCtx.Done():
			s.sched.ClearFreshOuterPending()
			return
		case <-ticker.C:
			if s.retransmitDue() {
				return
			}
		}
	}
}

func (s *Stream) sendFrame(ctx context.Context, f Frame, class FrameClass) error {
	if s.sched != nil {
		// Active mode intentionally preserves the Cycle 1 single-outer fast path:
		// no T1 budget checks, no estimator accounting, and no scheduler mutexes on
		// the hot DATA path. Once the detector leaves active mode, all DATA frames
		// go through Scheduler.AssignFrame so cautious mode can enforce the hard cap
		// and rotate outers.
		if class == FrameClassFreshData && s.sched.Mode() == SessionActive {
			// Fix 3 (Cycle 3.1): guard against stale s.tr after rotation+CleanExit.
			// s.tr is bound at NewStream time and never reassigned; after a cautious
			// rotation followed by decay back to active, it may reference a drained
			// transport. Fall through to AssignFrame if it's not active.
			if tr := s.tr; tr != nil && tr.State() == TransportActive {
				f.Header.TransportEpoch = tr.Epoch()
				return tr.SendFrame(ctx, f)
			}
		}
		// Fix 1 (Cycle 3.1): on ErrSchedulerBackpressure for FreshData, do not
		// propagate the error immediately. Wait for the client to REBIND a fresh
		// outer (signalled via Scheduler.transportCond) and retry once. Bounded
		// wait of 5 s (or shorter ctx deadline). This converts the failure from
		// "Stream dies in <2 s" to "Stream waits for fresh outer, then completes".
		if class == FrameClassFreshData {
			s.drainRetransmitsBeforeFreshData(ctx)
			tr, err := s.sched.AssignFrame(ctx, f, ScheduleOptions{Class: class})
			if err == nil {
				_ = tr
				return nil
			}
			if !errors.Is(err, ErrSchedulerBackpressure) {
				return err
			}
			// Backpressure — wait up to 5 s for a new transport.
			waitCtx, waitCancel := s.contextForWaitDeadline(ctx, 5*time.Second)
			defer waitCancel()
			if waitErr := s.sched.WaitForTransport(waitCtx); waitErr != nil {
				return err // timeout or ctx cancelled — propagate original
			}
			s.drainRetransmitsBeforeFreshData(ctx)
			// Retry once with the freshly-added transport.
			tr, err = s.sched.AssignFrame(ctx, f, ScheduleOptions{Class: class})
			if err != nil {
				return err
			}
			_ = tr
			return nil
		}
		tr, err := s.sched.AssignFrame(ctx, f, ScheduleOptions{Class: class})
		if err != nil {
			return err
		}
		_ = tr
		return nil
	}
	if s.tr != nil {
		return s.tr.SendFrame(ctx, f)
	}
	return nil
}

func (s *Stream) sendAck(ack uint64, sack []Range) error {
	ft := FrameACK
	var payload []byte
	var err error
	if len(sack) > 0 {
		ft = FrameSACK
		payload, err = MarshalSACK(sack)
		if err != nil {
			return err
		}
	}
	f := Frame{Header: FrameHeader{Version: Version1, Type: ft, Flags: s.direction, HeaderLen: HeaderLenV1, SessionID: s.sessionID, TransportEpoch: s.epoch(), StreamID: s.id, AckOffset: ack}, Payload: payload}
	return s.sendFrame(context.Background(), f, FrameClassControl)
}

func (s *Stream) maybeSendAck(ack uint64, sack []Range, force bool) error {
	if force || len(sack) > 0 {
		return s.sendAckNow(ack, sack)
	}

	s.ackMu.Lock()
	s.ackPending = true
	s.ackPendingOff = ack
	s.ackPendingSACK = nil
	s.ackCoalesce++
	if s.ackCoalesce < streamAckCoalesceFrames {
		s.scheduleAckCoalesceIdleLocked()
		s.ackMu.Unlock()
		return nil
	}
	ack, sack, ok := s.popPendingAckLocked()
	s.ackMu.Unlock()
	if !ok {
		return nil
	}
	return s.sendAck(ack, sack)
}

func (s *Stream) sendAckNow(ack uint64, sack []Range) error {
	s.ackMu.Lock()
	s.clearPendingAckLocked()
	s.ackMu.Unlock()
	return s.sendAck(ack, sack)
}

func (s *Stream) flushPendingAck() error {
	s.ackMu.Lock()
	ack, sack, ok := s.popPendingAckLocked()
	s.ackMu.Unlock()
	if !ok {
		return nil
	}
	return s.sendAck(ack, sack)
}

func (s *Stream) forceFlushAck() {
	_ = s.flushPendingAck()
}

func (s *Stream) scheduleAckCoalesceIdleLocked() {
	if s.ackCoalesceIdle != nil {
		return
	}
	s.ackCoalesceIdle = s.clock.AfterFunc(streamAckCoalesceIdleDelay, func() {
		_ = s.flushPendingAck()
	})
}

func (s *Stream) popPendingAckLocked() (uint64, []Range, bool) {
	if !s.ackPending {
		s.clearPendingAckLocked()
		return 0, nil, false
	}
	ack := s.ackPendingOff
	sack := append([]Range(nil), s.ackPendingSACK...)
	s.clearPendingAckLocked()
	return ack, sack, true
}

func (s *Stream) clearPendingAckLocked() {
	s.ackPending = false
	s.ackPendingOff = 0
	s.ackPendingSACK = nil
	s.ackCoalesce = 0
	if s.ackCoalesceIdle != nil {
		s.ackCoalesceIdle.Stop()
		s.ackCoalesceIdle = nil
	}
}

func (s *Stream) stopAckCoalesceIdleTimer() {
	s.ackMu.Lock()
	if s.ackCoalesceIdle != nil {
		s.ackCoalesceIdle.Stop()
		s.ackCoalesceIdle = nil
	}
	s.ackMu.Unlock()
}

func (s *Stream) readableBytesLocked() int {
	return len(s.readBuf) - s.readBufStart
}

func (s *Stream) resetReadBufferLocked() {
	s.readBuf = nil
	s.readBufStart = 0
}

func (s *Stream) sendRST(p RSTPayload) error {
	payload, err := MarshalRST(p)
	if err != nil {
		return err
	}
	f := Frame{Header: FrameHeader{Version: Version1, Type: FrameRST, Flags: s.direction, HeaderLen: HeaderLenV1, SessionID: s.sessionID, TransportEpoch: s.epoch(), StreamID: s.id}, Payload: payload}
	return s.sendFrame(context.Background(), f, FrameClassControl)
}

func (s *Stream) maybeEmitWindowUpdate(ack uint64, force bool) {
	s.wuMu.Lock()
	if ack <= s.lastWUOffset {
		s.wuMu.Unlock()
		return
	}
	if !force && ack-s.lastWUOffset < s.windowUpdateThreshold() {
		s.scheduleWindowUpdateIdleLocked()
		s.wuMu.Unlock()
		return
	}
	s.lastWUOffset = ack
	if s.wuIdleTimer != nil {
		s.wuIdleTimer.Stop()
		s.wuIdleTimer = nil
	}
	s.wuMu.Unlock()
	s.emitWindowUpdateAt(ack)
}

func (s *Stream) scheduleWindowUpdateIdleLocked() {
	if s.wuIdleTimer != nil {
		s.wuIdleTimer.Stop()
	}
	s.wuIdleTimer = s.clock.AfterFunc(streamWindowUpdateIdleDelay, func() {
		s.mu.Lock()
		if s.closed || s.state == StreamStateReset {
			s.mu.Unlock()
			return
		}
		ack, _ := s.reasm.AckState()
		s.mu.Unlock()
		s.maybeEmitWindowUpdate(ack, true)
	})
}

func (s *Stream) forceFlushWindowUpdate() {
	s.mu.Lock()
	ack, _ := s.reasm.AckState()
	s.mu.Unlock()
	s.maybeEmitWindowUpdate(ack, true)
}

func (s *Stream) stopWindowUpdateIdleTimer() {
	s.wuMu.Lock()
	if s.wuIdleTimer != nil {
		s.wuIdleTimer.Stop()
		s.wuIdleTimer = nil
	}
	s.wuMu.Unlock()
}

func (s *Stream) emitWindowUpdateAt(ack uint64) {
	end := ack + s.recvWindow
	if s.sink != nil {
		s.sink(StreamWindowUpdateEvent{
			StreamID:        s.id,
			WindowEndOffset: end,
			BufferedBytes:   s.reasm.BufferedBytes(),
			Time:            s.clock.Now(),
		})
	}
	if s.tr == nil && s.sched == nil {
		return
	}
	payload, err := MarshalWindowUpdate(WindowUpdatePayload{WindowEndOffset: end})
	if err != nil {
		return
	}
	f := Frame{Header: FrameHeader{
		Version: Version1, Type: FrameWINDOWUPDATE, Flags: s.direction,
		HeaderLen: HeaderLenV1, SessionID: s.sessionID,
		TransportEpoch: s.epoch(), StreamID: s.id,
	}, Payload: payload}
	s.wuMu.Lock()
	ch := s.outboundWUs
	if ch == nil {
		s.wuMu.Unlock()
		return
	}
	select {
	case ch <- f:
	default:
	}
	s.wuMu.Unlock()
}

func (s *Stream) applyLocked(event StreamEvent, ft FrameType) error {
	next, ok := nextStreamState(s.state, event)
	if !ok {
		return streamStateProtocolError(s.id, ft, "illegal stream transition")
	}
	s.state = next
	return nil
}

func (s *Stream) contextForDeadline(deadline time.Time) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(s.ctx)
	if deadline.IsZero() {
		return ctx, cancel
	}
	d := deadline.Sub(s.clock.Now())
	if d <= 0 {
		cancel()
		return ctx, cancel
	}
	tm := s.clock.AfterFunc(d, cancel)
	return ctx, func() { tm.Stop(); cancel() }
}

// contextForWaitDeadline creates a child of parent ctx bounded by the shorter
// of parent's deadline or maxWait. Used by sendFrame for backpressure waits.
func (s *Stream) contextForWaitDeadline(parent context.Context, maxWait time.Duration) (context.Context, context.CancelFunc) {
	// Compute effective timeout.
	remaining := maxWait
	if dl, ok := parent.Deadline(); ok {
		until := time.Until(dl)
		if until < remaining {
			remaining = until
		}
	}
	if remaining <= 0 {
		c := context.CancelFunc(func() {})
		return parent, c
	}
	return context.WithTimeout(parent, remaining)
}

func (s *Stream) stopTimersLocked() {
	if s.readTimer != nil {
		s.readTimer.Stop()
	}
	if s.writeTimer != nil {
		s.writeTimer.Stop()
	}
}
func (s *Stream) mapWriteError(err error) error {
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeExpired {
		return ErrStreamDeadlineExceeded
	}
	if s.resetErr != nil {
		return s.resetErr
	}
	return net.ErrClosed
}
