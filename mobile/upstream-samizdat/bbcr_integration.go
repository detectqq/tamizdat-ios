package samizdat

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/samizdat/bbcr"
)

const clientStallRescueDebounce = 750 * time.Millisecond // P0.5 Cycle 7-A: faster client rescue when MAY_REBIND lost to iptables freeze

// clientMayRebindReceived counts MAY_REBIND advisory frames received from the
// server. Added in P0.5 Cycle 3.2 so dashboards can correlate server-emitted
// rebind hints with the client's downstream prewarm reactions.
var clientMayRebindReceived = expvar.NewInt("samizdat.bbcr.client.may_rebind_received")

const bbcrSessionAuthority = "bbcr.session"

const (
	bbcrH2PipeBufferSize    = 64 * 1024
	bbcrH2PipeFlushInterval = 5 * time.Millisecond
)

const (
	bbcrOpenAddrIPv4   uint8  = 0x01
	bbcrOpenAddrDNS    uint8  = 0x03
	bbcrOpenAddrIPv6   uint8  = 0x04
	bbcrOpenNetworkTCP uint8  = 0x01
	bbcrRSTDialFailed  uint16 = 1
	bbcrRSTProtocol    uint16 = 2
)

type clientBBCR struct {
	client *Client
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	sessionID  uint64
	nextEpoch  uint32
	lastEpoch  uint32
	nextStream uint32
	outer      *clientBBCROuter
	sched      *bbcr.Scheduler
	creating   chan struct{}
	streams    map[uint32]*bbcr.Stream
	closed     bool

	lastInboundProgress time.Time
	lastInboundPrewarm  time.Time
}

type clientBBCROuter struct {
	*bbcr.OuterTransport
	parent *clientBBCR
	h2     *h2Transport
	pipe   *bbcrH2Pipe
	mu     sync.Mutex
	closed bool
}

type bbcrH2Pipe struct {
	body   io.ReadCloser
	writer io.WriteCloser
	bufw   *bufio.Writer
	resp   *http.Response
	mu     sync.Mutex

	flushStop chan struct{}
	flushDone chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newClientBBCR(c *Client) (*clientBBCR, error) {
	var idBytes [8]byte
	if _, err := io.ReadFull(rand.Reader, idBytes[:]); err != nil {
		return nil, fmt.Errorf("generating bbcr session id: %w", err)
	}
	id := binary.BigEndian.Uint64(idBytes[:])
	if id == 0 {
		id = 1
	}
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	b := &clientBBCR{client: c, ctx: ctx, cancel: cancel, sessionID: id, nextStream: 1, streams: make(map[uint32]*bbcr.Stream), lastInboundProgress: now}
	churnGate, _ := bbcr.NewChurnDialGate(bbcr.DefaultChurnConfig())
	b.sched = bbcr.NewScheduler(bbcr.SchedulerConfig{
		DialKey:        bbcr.DialKey{ServerIP: c.config.ServerAddr, SNI: c.config.ServerName},
		DialGate:       churnGate,
		AlwaysCautious: c.config.BBCRAlwaysCautious,
		Prewarm: func(ctx context.Context) (bbcr.Transport, error) {
			return b.prewarmOuter(ctx)
		},
	})
	go b.detectorLoop()
	return b, nil
}

func (b *clientBBCR) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("bbcr supports tcp only, got %s", network)
	}
	outer, err := b.ensureOuter(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := bbcrOpenStreamPayloadFromAddress(address)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, net.ErrClosed
	}
	streamID := b.nextStream
	b.nextStream += 2
	st, err := bbcr.NewStream(bbcr.StreamConfig{
		StreamID:             streamID,
		SessionID:            b.sessionID,
		Direction:            0,
		Transport:            outer,
		Scheduler:            b.sched,
		EnableRetransmitLoop: true,
		LocalAddr:            &streamAddr{network: "bbcr", address: "client"},
		RemoteAddr:           &streamAddr{network: network, address: address},
	})
	if err != nil {
		b.mu.Unlock()
		return nil, err
	}
	b.streams[streamID] = st
	b.mu.Unlock()

	open := bbcr.Frame{Header: bbcr.FrameHeader{Version: bbcr.Version1, Type: bbcr.FrameOPENSTREAM, HeaderLen: bbcr.HeaderLenV1, SessionID: b.sessionID, TransportEpoch: outer.Epoch(), StreamID: streamID}, Payload: payload}
	_, err = b.sched.AssignFrame(ctx, open, bbcr.ScheduleOptions{Class: bbcr.FrameClassControl})
	if err != nil {
		b.removeStream(streamID)
		_ = st.Close()
		return nil, fmt.Errorf("bbcr OPEN_STREAM: %w", err)
	}
	return &bbcrClientConn{BBCRStream: st, onClose: func() { b.removeStream(streamID) }}, nil
}

func (b *clientBBCR) ensureOuter(ctx context.Context) (*clientBBCROuter, error) {
	for {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return nil, net.ErrClosed
		}
		if b.outer != nil && !b.outer.isClosed() {
			outer := b.outer
			b.mu.Unlock()
			return outer, nil
		}
		if ch := b.creating; ch != nil {
			b.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ch:
				continue
			}
		}
		b.mu.Unlock()
		outer, err := b.prewarmOuter(ctx)
		if err != nil {
			return nil, err
		}
		return outer, nil
	}
}

func (b *clientBBCR) prewarmOuter(ctx context.Context) (*clientBBCROuter, error) {
	for {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return nil, net.ErrClosed
		}
		if ch := b.creating; ch != nil {
			b.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ch:
				b.mu.Lock()
				outer := b.outer
				b.mu.Unlock()
				if outer != nil && !outer.isClosed() {
					return outer, nil
				}
				continue
			}
		}
		b.creating = make(chan struct{})
		b.nextEpoch++
		epoch := b.nextEpoch
		previous := b.lastEpoch
		prev := b.outer
		b.mu.Unlock()

		outer, err := b.createOuter(ctx, epoch, previous)

		b.mu.Lock()
		ch := b.creating
		b.creating = nil
		if err == nil && !b.closed {
			b.outer = outer
			b.lastEpoch = epoch
			if b.sched != nil {
				b.sched.AddTransport(outer)
			}
			if prev != nil && !prev.isClosed() {
				prev.MarkDraining()
			}
		}
		b.mu.Unlock()
		if ch != nil {
			close(ch)
		}
		if err != nil {
			return nil, err
		}
		b.mu.Lock()
		closed := b.closed
		b.mu.Unlock()
		if closed {
			_ = outer.Close(net.ErrClosed)
			return nil, net.ErrClosed
		}
		go b.readLoop(outer)
		return outer, nil
	}
}

func (b *clientBBCR) createOuter(ctx context.Context, epoch, previous uint32) (*clientBBCROuter, error) {
	h2, err := b.client.createTransport(ctx)
	if err != nil {
		return nil, err
	}
	pipe, err := h2.openBBCRPipe(b.ctx)
	if err != nil {
		_ = h2.close()
		return nil, err
	}
	outer := &clientBBCROuter{parent: b, h2: h2, pipe: pipe}
	outer.OuterTransport = bbcr.NewOuterTransport(bbcr.OuterTransportConfig{
		Epoch:               epoch,
		RemainingPcapBudget: bbcr.HardCapPcap - bbcr.DefaultFixedS2CBudget,
		Send:                outer.writeFrame,
		Close:               func(error) error { return outer.closeUnderlying() },
	})
	outer.MarkActive()
	if err := outer.sendRebindAndWait(ctx, previous); err != nil {
		_ = outer.Close(err)
		return nil, err
	}
	return outer, nil
}

func (b *clientBBCR) readLoop(outer *clientBBCROuter) {
	var readErr error
	defer func() { _ = outer.Close(readErr) }()
	for {
		f, err := bbcr.DecodeFrame(outer.pipe.body, bbcr.DecodeOptions{LocalRole: bbcr.RoleClient, ValidateDirection: true})
		if err != nil {
			readErr = err
			return
		}
		if f.Header.Type == bbcr.FrameREBIND && f.Header.StreamID == 0 {
			b.markInboundProgress()
			continue
		}
		if f.Header.Type == bbcr.FrameMAYREBIND && f.Header.StreamID == 0 {
			// P0.5 Cycle 3.2: server-emitted advisory that an outer is about to
			// hit its packet-capture cap. Treat as a strong signal to dial a
			// fresh outer immediately, bypassing the inbound-stall cooldown.
			clientMayRebindReceived.Add(1)
			b.markInboundProgress()
			b.forcePrewarm()
			continue
		}
		if f.Header.Type == bbcr.FrameNOISE && f.Header.StreamID == 0 {
			bbcrNoiseFramesReceived.Add(1)
			b.markInboundProgress()
			continue
		}
		b.markInboundProgress()
		b.mu.Lock()
		st := b.streams[f.Header.StreamID]
		b.mu.Unlock()
		if st == nil {
			continue
		}
		_ = deliverBBCRFrameToStream(st, f)
	}
}

func (b *clientBBCR) detectorLoop() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if b.sched != nil {
				b.sched.CheckACKStall(b.totalUnackedBytes())
				b.sched.CheckCleanExit()
			}
			b.prewarmOnInboundStall()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *clientBBCR) markInboundProgress() {
	b.mu.Lock()
	b.lastInboundProgress = time.Now()
	b.mu.Unlock()
}

// forcePrewarm dials a fresh outer immediately, bypassing the inbound-stall
// debounce. Called from the readLoop on receipt of a server-emitted MAY_REBIND
// advisory frame. P0.5 Cycle 3.2.
func (b *clientBBCR) forcePrewarm() {
	b.mu.Lock()
	if b.closed || b.creating != nil {
		b.mu.Unlock()
		return
	}
	b.lastInboundPrewarm = time.Now()
	b.mu.Unlock()
	go func() {
		ctx := ctxWithForcedPrewarm(b.ctx)
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		_, _ = b.prewarmOuter(ctx)
	}()
}

func (b *clientBBCR) prewarmOnInboundStall() {
	now := time.Now()
	b.mu.Lock()
	if b.closed || len(b.streams) == 0 || b.creating != nil {
		b.mu.Unlock()
		return
	}
	if b.lastInboundProgress.IsZero() {
		b.lastInboundProgress = now
		b.mu.Unlock()
		return
	}
	if now.Sub(b.lastInboundProgress) < clientStallRescueDebounce {
		b.mu.Unlock()
		return
	}
	if !b.lastInboundPrewarm.IsZero() && now.Sub(b.lastInboundPrewarm) < clientStallRescueDebounce {
		b.mu.Unlock()
		return
	}
	b.lastInboundPrewarm = now
	b.mu.Unlock()

	if b.sched != nil {
		b.sched.CheckACKStall(bbcr.AckStallUnackedThreshold + 1)
	}
	ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	defer cancel()
	_, _ = b.prewarmOuter(ctx)
}

func (b *clientBBCR) totalUnackedBytes() uint64 {
	b.mu.Lock()
	streams := make([]*bbcr.Stream, 0, len(b.streams))
	for _, st := range b.streams {
		streams = append(streams, st)
	}
	b.mu.Unlock()
	var total uint64
	for _, st := range streams {
		total += st.UnackedBytes()
	}
	return total
}

func (b *clientBBCR) removeStream(id uint32) {
	b.mu.Lock()
	delete(b.streams, id)
	b.mu.Unlock()
}

func (b *clientBBCR) close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	outer := b.outer
	cancel := b.cancel
	streams := make([]*bbcr.Stream, 0, len(b.streams))
	for _, st := range b.streams {
		streams = append(streams, st)
	}
	b.streams = make(map[uint32]*bbcr.Stream)
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, st := range streams {
		_ = st.Close()
	}
	if b.sched != nil {
		b.sched.Close()
	}
	if outer != nil {
		return outer.Close(nil)
	}
	return nil
}

func (o *clientBBCROuter) sendRebindAndWait(ctx context.Context, previous uint32) error {
	payload, err := bbcr.MarshalRebind(bbcr.RebindPayload{Mode: bbcr.RebindModeRequest, PreviousEpoch: previous, MaxFramePayload: bbcr.MaxFramePayload})
	if err != nil {
		return err
	}
	f := bbcr.Frame{Header: bbcr.FrameHeader{Version: bbcr.Version1, Type: bbcr.FrameREBIND, HeaderLen: bbcr.HeaderLenV1, Flags: bbcr.FlagPriorityControl, SessionID: o.parent.sessionID, TransportEpoch: o.Epoch()}, Payload: payload}
	if err := o.SendFrame(ctx, f); err != nil {
		return err
	}
	accept, err := bbcr.DecodeFrame(o.pipe.body, bbcr.DecodeOptions{LocalRole: bbcr.RoleClient, ValidateDirection: true})
	if err != nil {
		return err
	}
	if accept.Header.Type != bbcr.FrameREBIND || accept.Header.SessionID != o.parent.sessionID || accept.Header.TransportEpoch != o.Epoch() {
		return fmt.Errorf("bbcr rebind: unexpected accept frame")
	}
	rp, err := bbcr.ParseRebind(accept.Payload)
	if err != nil {
		return err
	}
	if rp.Mode != bbcr.RebindModeAccept {
		return fmt.Errorf("bbcr rebind rejected: code=%d", rp.ReasonCode)
	}
	return nil
}

func (o *clientBBCROuter) writeFrame(ctx context.Context, f bbcr.Frame) error {
	if f.Header.TransportEpoch == 0 {
		f.Header.TransportEpoch = o.Epoch()
	}
	if f.Header.SessionID == 0 {
		f.Header.SessionID = o.parent.sessionID
	}
	return o.pipe.writeFrame(ctx, o.h2.shaper, o.h2.fragmenter, f)
}
func (o *clientBBCROuter) Close(err error) error {
	if err != nil && o.parent != nil && o.parent.sched != nil {
		o.parent.sched.ObserveTransportTeardown(bbcr.TransportTeardownEvent{Epoch: o.Epoch(), EmittedBytes: bbcr.HardCapPcap - o.RemainingPcapBudget(), Err: err})
	}
	if o.OuterTransport != nil {
		return o.OuterTransport.Close(err)
	}
	return o.closeUnderlying()
}
func (o *clientBBCROuter) closeUnderlying() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	o.mu.Unlock()
	if o.pipe != nil {
		_ = o.pipe.close()
	}
	if o.h2 != nil {
		return o.h2.close()
	}
	return nil
}
func (o *clientBBCROuter) isClosed() bool { o.mu.Lock(); defer o.mu.Unlock(); return o.closed }

func (p *bbcrH2Pipe) writeFrame(ctx context.Context, shaper *Shaper, fragmenter *RecordFragmenter, f bbcr.Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	wire, err := bbcr.MarshalFrame(f.Header, f.Payload)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w := io.Writer(p.writer)
	if p.bufw != nil {
		w = p.bufw
	}
	if shaper != nil {
		_, err = shaper.FragmentWrite(w, fragmenter, wire)
	} else {
		_, err = w.Write(wire)
	}
	if err != nil {
		return err
	}
	_, hasDeadline := ctx.Deadline()
	if f.Header.Type != bbcr.FrameDATA || hasDeadline {
		return p.flushLocked(ctx)
	}
	return ctx.Err()
}

func (p *bbcrH2Pipe) flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.flushLocked(ctx)
}

func (p *bbcrH2Pipe) flushLocked(ctx context.Context) error {
	if p.bufw == nil || p.bufw.Buffered() == 0 {
		return ctx.Err()
	}
	if err := p.bufw.Flush(); err != nil {
		return err
	}
	return ctx.Err()
}

func (p *bbcrH2Pipe) flushLoop() {
	ticker := time.NewTicker(bbcrH2PipeFlushInterval)
	defer ticker.Stop()
	defer close(p.flushDone)
	for {
		select {
		case <-ticker.C:
			_ = p.flush(context.Background())
		case <-p.flushStop:
			return
		}
	}
}

func (p *bbcrH2Pipe) close() error {
	p.closeOnce.Do(func() {
		if p.flushStop != nil {
			close(p.flushStop)
			<-p.flushDone
		}
		p.mu.Lock()
		if p.bufw != nil {
			if err := p.bufw.Flush(); err != nil && p.closeErr == nil {
				p.closeErr = err
			}
		}
		if p.writer != nil {
			if err := p.writer.Close(); err != nil && p.closeErr == nil {
				p.closeErr = err
			}
		}
		if p.body != nil {
			_ = p.body.Close()
		}
		p.mu.Unlock()
	})
	return p.closeErr
}

func newBBCRH2Pipe(body io.ReadCloser, writer io.WriteCloser, resp *http.Response) *bbcrH2Pipe {
	p := &bbcrH2Pipe{body: body, writer: writer, resp: resp, bufw: bufio.NewWriterSize(writer, bbcrH2PipeBufferSize), flushStop: make(chan struct{}), flushDone: make(chan struct{})}
	go p.flushLoop()
	return p
}

func (t *h2Transport) openBBCRPipe(ctx context.Context) (*bbcrH2Pipe, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("transport closed")
	}
	t.mu.Unlock()
	t.touch()
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+t.serverAddr, pr)
	if err != nil {
		_ = pw.Close()
		return nil, err
	}
	req.Host = bbcrSessionAuthority
	resp, err := t.h2Roundtrip.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		return nil, fmt.Errorf("CONNECT %s: %w", bbcrSessionAuthority, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("CONNECT %s returned status %d", bbcrSessionAuthority, resp.StatusCode)
	}
	t.activeStreams.Add(1)
	return newBBCRH2Pipe(resp.Body, pw, resp), nil
}

type bbcrClientConn struct {
	bbcr.BBCRStream
	once    sync.Once
	onClose func()
}

func (c *bbcrClientConn) Close() error {
	err := c.BBCRStream.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func deliverBBCRFrameToStream(st *bbcr.Stream, f bbcr.Frame) error {
	switch f.Header.Type {
	case bbcr.FrameDATA:
		return st.ReceiveData(f.Header.SeqOffset, f.Payload)
	case bbcr.FrameFIN:
		return st.ReceiveFIN(f.Header.SeqOffset)
	case bbcr.FrameACK:
		return st.HandleACK(f.Header.AckOffset)
	case bbcr.FrameSACK:
		r, err := bbcr.ParseSACK(f.Payload, f.Header.AckOffset)
		if err != nil {
			return err
		}
		return st.HandleSACK(f.Header.AckOffset, r)
	case bbcr.FrameRST:
		p, err := bbcr.ParseRST(f.Payload)
		if err != nil {
			return err
		}
		return st.ReceiveRST(p)
	case bbcr.FrameWINDOWUPDATE:
		p, err := bbcr.ParseWindowUpdate(f.Payload)
		if err != nil {
			return err
		}
		return st.HandleWindowUpdate(p.WindowEndOffset)
	default:
		return nil
	}
}

func bbcrOpenStreamPayloadFromAddress(address string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port64 == 0 {
		return nil, fmt.Errorf("invalid port in %q", address)
	}
	var at uint8
	var hostBytes []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			at = bbcrOpenAddrIPv4
			hostBytes = append([]byte(nil), v4...)
		} else {
			at = bbcrOpenAddrIPv6
			hostBytes = append([]byte(nil), ip.To16()...)
		}
	} else {
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			return nil, fmt.Errorf("empty host")
		}
		at = bbcrOpenAddrDNS
		hostBytes = []byte(host)
	}
	return bbcr.MarshalOpenStream(bbcr.OpenStreamPayload{AddressType: at, Network: bbcrOpenNetworkTCP, Port: uint16(port64), Host: hostBytes})
}

func bbcrDestinationFromOpenPayload(payload []byte) (string, error) {
	p, err := bbcr.ParseOpenStream(payload)
	if err != nil {
		return "", err
	}
	var host string
	switch p.AddressType {
	case bbcrOpenAddrIPv4, bbcrOpenAddrIPv6:
		host = net.IP(p.Host).String()
	case bbcrOpenAddrDNS:
		host = string(p.Host)
	default:
		return "", fmt.Errorf("unsupported address type %d", p.AddressType)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p.Port))), nil
}
