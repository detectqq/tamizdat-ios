package samizdat

import (
	"bufio"
	"context"
	"errors"
	"expvar"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/getlantern/samizdat/bbcr"
)

var schedDbg = expvar.NewMap("samizdat.bbcr.server.prewarm_dbg")

type serverBBCROuter struct {
	transport  *bbcr.OuterTransport
	writer     flushWriter
	bufw       *bufio.Writer
	shaper     *Shaper
	fragmenter *RecordFragmenter
	scheduler  *bbcr.Scheduler
	mu         sync.Mutex
	closed     bool
	flushDirty bool

	flushStop chan struct{}
	flushDone chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (s *Server) serveBBCRConnect(w http.ResponseWriter, r *http.Request, identity [8]byte) {
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	auth := bbcr.AuthIdentity(identity)
	outer := &serverBBCROuter{writer: flushWriter{w: w, flusher: flusher}, shaper: s.shaper, fragmenter: s.fragmenter}
	defer outer.markClosed()
	tr := bbcr.NewOuterTransport(bbcr.OuterTransportConfig{
		RemainingPcapBudget: bbcr.HardCapPcap - bbcr.DefaultFixedS2CBudget,
		Send:                outer.sendFrame,
		Close:               func(error) error { outer.markClosed(); return nil },
	})
	outer.transport = tr

	first, err := bbcr.DecodeFrame(r.Body, bbcr.DecodeOptions{LocalRole: bbcr.RoleServer, ValidateDirection: true})
	if err != nil {
		_ = tr.Close(err)
		return
	}
	sess, err := s.bbcrSessions.AttachTransport(r.Context(), auth, tr, first)
	if err != nil {
		return
	}
	// P0.5 Cycle 3.2 (validator audit d31a51a): the server cannot dial new outers
	// itself, but it must still be able to drive REBIND when its scheduler hits
	// cap exhaustion. Wire a Prewarm callback that emits a MAY_REBIND advisory
	// frame on any active outer and waits on transportCond for the client-driven
	// new transport to arrive via AddTransport. The closure captures the
	// scheduler via late binding (sched is set after EnsureScheduler returns).
	var sched *bbcr.Scheduler
	prewarmCB := func(ctx context.Context) (bbcr.Transport, error) {
		if sched == nil {
			schedDbg.Add("prewarm_nil_sched", 1)
			return nil, bbcr.ErrSchedulerBackpressure
		}
		signalTr := sched.AnyActiveTransport()
		if signalTr == nil {
			schedDbg.Add("prewarm_no_signal_tr", 1)
			return nil, bbcr.ErrSchedulerBackpressure
		}
		oldEpochs := sched.SnapshotActiveEpochs()
		mayRebind := bbcr.Frame{Header: bbcr.FrameHeader{
			Version: bbcr.Version1, Type: bbcr.FrameMAYREBIND, HeaderLen: bbcr.HeaderLenV1,
			Flags:          bbcr.FlagDirS2C | bbcr.FlagPriorityControl,
			SessionID:      first.Header.SessionID,
			TransportEpoch: signalTr.Epoch(),
		}}
		// Use an aggressive deadline for the signal send; the wait below uses ctx.
		signalCtx, signalCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := signalTr.SendFrame(signalCtx, mayRebind); err != nil {
			signalCancel()
			schedDbg.Add("prewarm_signal_send_err", 1)
			_ = err
		} else {
			signalCancel()
			schedDbg.Add("prewarm_signal_sent", 1)
		}
		fresh, err := sched.WaitForNewTransport(ctx, oldEpochs)
		if err != nil {
			schedDbg.Add("prewarm_wait_err", 1)
			return nil, err
		}
		if fresh == nil {
			schedDbg.Add("prewarm_no_fresh_at_all", 1)
			return nil, bbcr.ErrSchedulerBackpressure
		}
		schedDbg.Add("prewarm_fresh_returned", 1)
		return fresh, nil
	}
	sched = sess.EnsureScheduler(bbcr.SchedulerConfig{
		AlwaysCautious: s.config.BBCRAlwaysCautious,
		Prewarm:        prewarmCB,
	})
	sched.AddTransport(tr)
	outer.scheduler = sched
	s.startBBCRNoiseLoop(r.Context(), first.Header.SessionID, sched)
	for {
		f, err := bbcr.DecodeFrame(r.Body, bbcr.DecodeOptions{LocalRole: bbcr.RoleServer, ValidateDirection: true})
		if err != nil {
			if !errors.Is(err, io.EOF) {
				if outer.scheduler != nil {
					outer.scheduler.ObserveTransportTeardown(bbcr.TransportTeardownEvent{Epoch: tr.Epoch(), EmittedBytes: bbcr.HardCapPcap - tr.RemainingPcapBudget(), Err: err})
				}
				_ = tr.Close(err)
			}
			return
		}
		if f.Header.Type == bbcr.FrameOPENSTREAM {
			s.handleBBCROpenStream(r.Context(), sess, f)
			continue
		}
		_ = sess.HandleFrame(f)
	}
}

func (s *Server) handleBBCROpenStream(ctx context.Context, sess *bbcr.Session, f bbcr.Frame) {
	destination, err := bbcrDestinationFromOpenPayload(f.Payload)
	if err != nil {
		sendBBCRRST(sess, f, bbcrRSTProtocol)
		return
	}
	stream, err := sess.OpenStream(f.Header.StreamID, bbcr.FlagDirS2C)
	if err != nil {
		sendBBCRRST(sess, f, bbcrRSTProtocol)
		return
	}
	go func() {
		defer stream.Close()
		s.config.Handler(ctx, stream, destination)
	}()
}

func sendBBCRRST(sess *bbcr.Session, f bbcr.Frame, code uint16) {
	st, err := sess.OpenStream(f.Header.StreamID, bbcr.FlagDirS2C)
	if err != nil {
		return
	}
	payload, err := bbcr.MarshalRST(bbcr.RSTPayload{ErrorCode: code})
	if err != nil {
		return
	}
	_ = st.ReceiveRST(bbcr.RSTPayload{ErrorCode: code})
	_ = sess.HandleFrame(bbcr.Frame{Header: bbcr.FrameHeader{Version: bbcr.Version1, Type: bbcr.FrameRST, HeaderLen: bbcr.HeaderLenV1, Flags: bbcr.FlagDirS2C, SessionID: f.Header.SessionID, TransportEpoch: f.Header.TransportEpoch, StreamID: f.Header.StreamID}, Payload: payload})
}

func (o *serverBBCROuter) sendFrame(ctx context.Context, f bbcr.Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return net.ErrClosed
	}
	o.ensureBufferedLocked()
	wire, err := bbcr.MarshalFrame(f.Header, f.Payload)
	if err != nil {
		return err
	}
	w := io.Writer(o.bufw)
	if o.shaper != nil {
		_, err = o.shaper.FragmentWrite(w, o.fragmenter, wire)
	} else {
		_, err = w.Write(wire)
	}
	if err != nil {
		return err
	}
	o.flushDirty = true
	_, hasDeadline := ctx.Deadline()
	if f.Header.Type != bbcr.FrameDATA || hasDeadline {
		return o.flushLocked(ctx)
	}
	return ctx.Err()
}

func (o *serverBBCROuter) markClosed() {
	_ = o.close()
}

func (o *serverBBCROuter) ensureBufferedLocked() {
	if o.bufw != nil {
		return
	}
	o.bufw = bufio.NewWriterSize(o.writer, bbcrH2PipeBufferSize)
	o.flushStop = make(chan struct{})
	o.flushDone = make(chan struct{})
	go o.flushLoop()
}

func (o *serverBBCROuter) flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.flushLocked(ctx)
}

func (o *serverBBCROuter) flushLocked(ctx context.Context) error {
	if o.bufw == nil {
		if o.flushDirty {
			o.writer.Flush()
			o.flushDirty = false
		}
		return ctx.Err()
	}
	if o.bufw.Buffered() > 0 {
		if err := o.bufw.Flush(); err != nil {
			return err
		}
	}
	if o.flushDirty {
		o.writer.Flush()
		o.flushDirty = false
	}
	return ctx.Err()
}

func (o *serverBBCROuter) flushLoop() {
	ticker := time.NewTicker(bbcrH2PipeFlushInterval)
	defer ticker.Stop()
	defer close(o.flushDone)
	for {
		select {
		case <-ticker.C:
			_ = o.flush(context.Background())
		case <-o.flushStop:
			return
		}
	}
}

func (o *serverBBCROuter) close() error {
	o.closeOnce.Do(func() {
		o.mu.Lock()
		stop := o.flushStop
		done := o.flushDone
		o.closed = true
		o.mu.Unlock()

		if stop != nil {
			close(stop)
			<-done
		}

		o.mu.Lock()
		if err := o.flushLocked(context.Background()); err != nil && o.closeErr == nil {
			o.closeErr = err
		}
		o.mu.Unlock()
	})
	return o.closeErr
}
