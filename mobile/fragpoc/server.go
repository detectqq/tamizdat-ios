package fragpoc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Handler func(ctx context.Context, conn net.Conn, destination string, shortID [ShortIDLen]byte)

type ServerConfig struct {
	ShortID             [ShortIDLen]byte
	Authorize           func([ShortIDLen]byte) bool
	Handler             Handler
	MaxPayload          int
	SessionTTL          time.Duration
	SessionReapInterval time.Duration
	DownReadTimeout     time.Duration
	OperationTimeout    time.Duration
	DestinationLimit    int
}

type Server struct {
	config              ServerConfig
	maxPayload          int
	sessionTTL          time.Duration
	sessionReapInterval time.Duration
	downReadTimeout     time.Duration
	operationTimeout    time.Duration
	destinationLimit    int

	mu       sync.Mutex
	sessions map[[SIDLen]byte]*session

	stop      chan struct{}
	closeOnce sync.Once
}

type session struct {
	sid        [SIDLen]byte
	conn       net.Conn
	createdAt  time.Time
	lastUsed   atomic.Int64
	closed     atomic.Bool
	secure     bool
	secureKey  [32]byte
	upMu       sync.Mutex
	downMu     sync.Mutex
	downSeq    uint32
	downReplay []downFrame
	downEOF    bool
}

type downFrame struct {
	seq  uint32
	data []byte
	eof  bool
}

const maxDownReplayFrames = 8

func NewServer(config ServerConfig) (*Server, error) {
	if config.Handler == nil {
		return nil, errors.New("fragpoc: Handler is required")
	}
	s := &Server{
		config:              config,
		maxPayload:          maxPayload(config.MaxPayload),
		sessionTTL:          durationDefault(config.SessionTTL, 5*time.Minute),
		sessionReapInterval: durationDefault(config.SessionReapInterval, 30*time.Second),
		downReadTimeout:     durationDefault(config.DownReadTimeout, 15*time.Second),
		operationTimeout:    durationDefault(config.OperationTimeout, 30*time.Second),
		destinationLimit:    intDefault(config.DestinationLimit, 512),
		sessions:            make(map[[SIDLen]byte]*session),
		stop:                make(chan struct{}),
	}
	go s.reaperLoop()
	return s, nil
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.ServeConn(ctx, conn)
	}
}

// SessionCount returns the number of live FragPoC sessions. Used by the
// dynamic port-manager as its load signal.
func (s *Server) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if s.operationTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.operationTimeout))
		defer conn.SetDeadline(time.Time{})
	}
	var op [1]byte
	if _, err := io.ReadFull(conn, op[:]); err != nil {
		return
	}
	switch op[0] {
	case OpOpen:
		s.handleOpen(ctx, conn)
	case OpUp:
		s.handleUp(conn)
	case OpDown:
		s.handleDown(conn)
	case OpClose:
		s.handleClose(conn)
	case OpOpenSecure:
		s.handleOpenSecure(ctx, conn)
	case OpUpSecure:
		s.handleUpSecure(conn)
	case OpDownSecure:
		s.handleDownSecure(conn)
	case OpCloseSecure:
		s.handleCloseSecure(conn)
	default:
		_, _ = conn.Write([]byte{AckErr})
	}
}

func (s *Server) handleOpen(ctx context.Context, conn net.Conn) {
	var shortID [ShortIDLen]byte
	if _, err := io.ReadFull(conn, shortID[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	if !s.authorize(shortID) {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	destination, err := readNULString(conn, s.destinationLimit)
	if err != nil || destination == "" {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	clientConn, serverConn := newBufferedPipe()
	sess := &session{
		conn:      clientConn,
		createdAt: time.Now(),
	}
	sess.touch()
	if _, err := io.ReadFull(rand.Reader, sess.sid[:]); err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	s.addSession(sess)
	resp := make([]byte, 1+SIDLen)
	resp[0] = AckOK
	copy(resp[1:], sess.sid[:])
	if _, err := conn.Write(resp); err != nil {
		s.deleteSession(sess.sid)
		sess.close()
		_ = serverConn.Close()
		return
	}
	go func() {
		defer s.deleteSession(sess.sid)
		defer sess.close()
		s.config.Handler(ctx, serverConn, destination, shortID)
	}()
}

func (s *Server) handleOpenSecure(ctx context.Context, conn net.Conn) {
	var shortID [ShortIDLen]byte
	if _, err := io.ReadFull(conn, shortID[:]); err != nil {
		return
	}
	staticKey := deriveSecureStaticKey(shortID)
	respAD := secureResponseAD(OpOpenSecure, shortID[:])
	plain, openNonce, err := readSecureBody(conn, staticKey, secureRequestAD(OpOpenSecure, shortID[:]), s.destinationLimit+1)
	if err != nil {
		return
	}
	writeErr := func() {
		_, _ = writeSecureBody(conn, staticKey, respAD, []byte{AckErr})
	}
	if !s.authorize(shortID) {
		writeErr()
		return
	}
	destination, err := readNULBytes(plain, s.destinationLimit)
	if err != nil || destination == "" {
		writeErr()
		return
	}
	clientConn, serverConn := newBufferedPipe()
	sess := &session{
		conn:      clientConn,
		createdAt: time.Now(),
		secure:    true,
	}
	sess.touch()
	if _, err := io.ReadFull(rand.Reader, sess.sid[:]); err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		writeErr()
		return
	}
	sess.secureKey = deriveSecureSessionKey(staticKey, sess.sid, openNonce)
	s.addSession(sess)
	resp := make([]byte, 1+SIDLen)
	resp[0] = AckOK
	copy(resp[1:], sess.sid[:])
	if _, err := writeSecureBody(conn, staticKey, respAD, resp); err != nil {
		s.deleteSession(sess.sid)
		sess.close()
		_ = serverConn.Close()
		return
	}
	go func() {
		defer s.deleteSession(sess.sid)
		defer sess.close()
		s.config.Handler(ctx, serverConn, destination, shortID)
	}()
}

func (s *Server) handleUp(conn net.Conn) {
	sess, ok := s.readSession(conn)
	if !ok {
		return
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > s.maxPayload {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	sess.upMu.Lock()
	if s.operationTimeout > 0 {
		_ = sess.conn.SetWriteDeadline(time.Now().Add(s.operationTimeout))
	}
	_, err := sess.conn.Write(buf)
	_ = sess.conn.SetWriteDeadline(time.Time{})
	sess.upMu.Unlock()
	if err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	sess.touch()
	_, _ = conn.Write([]byte{AckOK})
}

func (s *Server) handleUpSecure(conn net.Conn) {
	sess, ok := s.readSecureSession(conn, OpUpSecure)
	if !ok {
		return
	}
	respAD := secureResponseAD(OpUpSecure, sess.sid[:])
	writeErr := func() {
		_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckErr})
	}
	plain, _, err := readSecureBody(conn, sess.secureKey, secureRequestAD(OpUpSecure, sess.sid[:]), 2+s.maxPayload)
	if err != nil || len(plain) < 2 {
		writeErr()
		return
	}
	n := int(binary.BigEndian.Uint16(plain[:2]))
	if n > s.maxPayload || len(plain) != 2+n {
		writeErr()
		return
	}
	sess.upMu.Lock()
	if s.operationTimeout > 0 {
		_ = sess.conn.SetWriteDeadline(time.Now().Add(s.operationTimeout))
	}
	_, err = sess.conn.Write(plain[2:])
	_ = sess.conn.SetWriteDeadline(time.Time{})
	sess.upMu.Unlock()
	if err != nil {
		writeErr()
		return
	}
	sess.touch()
	_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckOK})
}

func (s *Server) handleDown(conn net.Conn) {
	sess, ok := s.readSession(conn)
	if !ok {
		return
	}
	ack, ok := readDownRequest(conn)
	if !ok {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	_, _ = conn.Write(s.nextDownResponse(sess, ack))
}

func (s *Server) handleDownSecure(conn net.Conn) {
	sess, ok := s.readSecureSession(conn, OpDownSecure)
	if !ok {
		return
	}
	respAD := secureResponseAD(OpDownSecure, sess.sid[:])
	writeErr := func() {
		_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckErr})
	}
	plain, _, err := readSecureBody(conn, sess.secureKey, secureRequestAD(OpDownSecure, sess.sid[:]), DownRequestSize)
	ack, ok := readDownRequestBytes(plain)
	if err != nil || !ok {
		writeErr()
		return
	}
	_, _ = writeSecureBody(conn, sess.secureKey, respAD, s.nextDownResponse(sess, ack))
}

func (s *Server) nextDownResponse(sess *session, ack uint32) []byte {
	buf := make([]byte, s.maxPayload)
	sess.downMu.Lock()
	defer sess.downMu.Unlock()
	sess.dropAckedDownFrames(ack)
	if len(sess.downReplay) > 0 {
		if len(sess.downReplay) >= maxDownReplayFrames || sess.downEOF {
			return encodeDownFrame(sess.replayDownFrame(ack))
		}
		if frame, ok := s.readDownFrameLocked(sess, buf, time.Millisecond); ok {
			sess.downReplay = append(sess.downReplay, frame)
			return encodeDownFrame(frame)
		}
		return encodeDownFrame(sess.replayDownFrame(ack))
	}
	if frame, ok := s.readDownFrameLocked(sess, buf, s.downReadTimeout); ok {
		sess.downReplay = append(sess.downReplay, frame)
		return encodeDownFrame(frame)
	}
	var zero [6]byte
	binary.BigEndian.PutUint32(zero[:4], sess.downSeq)
	return zero[:]
}

func (s *Server) readDownFrameLocked(sess *session, buf []byte, timeout time.Duration) (downFrame, bool) {
	if timeout <= 0 {
		timeout = time.Millisecond
	}
	_ = sess.conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := sess.conn.Read(buf)
	_ = sess.conn.SetReadDeadline(time.Time{})
	if n > 0 {
		sess.touch()
		seq := sess.downSeq
		sess.downSeq++
		return downFrame{seq: seq, data: append([]byte(nil), buf[:n]...)}, true
	}
	if err != nil {
		if isTimeout(err) {
			return downFrame{}, false
		}
		if sess.downEOF {
			return sess.replayDownFrame(sess.downSeq), true
		}
		seq := sess.downSeq
		sess.downSeq++
		sess.downEOF = true
		return downFrame{seq: seq, eof: true}, true
	}
	return downFrame{}, false
}

func encodeDownFrame(frame downFrame) []byte {
	resp := make([]byte, 6+len(frame.data))
	binary.BigEndian.PutUint32(resp[:4], frame.seq)
	if frame.eof {
		binary.BigEndian.PutUint16(resp[4:6], 0xffff)
		return resp[:6]
	}
	binary.BigEndian.PutUint16(resp[4:6], uint16(len(frame.data)))
	copy(resp[6:], frame.data)
	return resp
}

func (sess *session) dropAckedDownFrames(ack uint32) {
	if len(sess.downReplay) == 0 {
		return
	}
	keep := sess.downReplay[:0]
	for _, frame := range sess.downReplay {
		if frame.eof || frame.seq >= ack {
			keep = append(keep, frame)
		}
	}
	sess.downReplay = keep
}

func (sess *session) replayDownFrame(ack uint32) downFrame {
	if len(sess.downReplay) == 0 {
		seq := sess.downSeq
		if seq > 0 {
			seq--
		}
		return downFrame{seq: seq, eof: sess.downEOF}
	}
	for _, frame := range sess.downReplay {
		if frame.seq == ack {
			return frame
		}
	}
	for _, frame := range sess.downReplay {
		if frame.seq >= ack {
			return frame
		}
	}
	return sess.downReplay[len(sess.downReplay)-1]
}

func readDownRequest(conn net.Conn) (uint32, bool) {
	var hdr [6]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, false
	}
	ack := binary.BigEndian.Uint32(hdr[:4])
	n := int(binary.BigEndian.Uint16(hdr[4:]))
	if n < 0 || n > DownRequestSize {
		return 0, false
	}
	if n == 0 {
		return ack, true
	}
	_, err := io.CopyN(io.Discard, conn, int64(n))
	return ack, err == nil
}

func readDownRequestBytes(p []byte) (uint32, bool) {
	if len(p) < 6 {
		return 0, false
	}
	ack := binary.BigEndian.Uint32(p[:4])
	n := int(binary.BigEndian.Uint16(p[4:6]))
	if n < 0 || n > DownRequestSize {
		return 0, false
	}
	return ack, len(p) == 6+n
}

func (s *Server) handleClose(conn net.Conn) {
	var sid [SIDLen]byte
	if _, err := io.ReadFull(conn, sid[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return
	}
	if sess := s.deleteSession(sid); sess != nil {
		sess.close()
	}
	_, _ = conn.Write([]byte{AckOK})
}

func (s *Server) handleCloseSecure(conn net.Conn) {
	sess, ok := s.readSecureSession(conn, OpCloseSecure)
	if !ok {
		return
	}
	respAD := secureResponseAD(OpCloseSecure, sess.sid[:])
	if _, _, err := readSecureBody(conn, sess.secureKey, secureRequestAD(OpCloseSecure, sess.sid[:]), 0); err != nil {
		_, _ = writeSecureBody(conn, sess.secureKey, respAD, []byte{AckErr})
		return
	}
	secureKey := sess.secureKey
	sid := sess.sid
	if deleted := s.deleteSession(sid); deleted != nil {
		deleted.close()
	}
	_, _ = writeSecureBody(conn, secureKey, respAD, []byte{AckOK})
}

func (s *Server) readSession(conn net.Conn) (*session, bool) {
	var sid [SIDLen]byte
	if _, err := io.ReadFull(conn, sid[:]); err != nil {
		_, _ = conn.Write([]byte{AckErr})
		return nil, false
	}
	sess := s.getSession(sid)
	if sess == nil {
		_, _ = conn.Write([]byte{AckErr})
		return nil, false
	}
	if sess.secure {
		_, _ = conn.Write([]byte{AckErr})
		return nil, false
	}
	return sess, true
}

func (s *Server) readSecureSession(conn net.Conn, op byte) (*session, bool) {
	var sid [SIDLen]byte
	if _, err := io.ReadFull(conn, sid[:]); err != nil {
		return nil, false
	}
	sess := s.getSession(sid)
	if sess == nil || !sess.secure {
		return nil, false
	}
	return sess, true
}

func (s *Server) authorize(shortID [ShortIDLen]byte) bool {
	if s.config.Authorize != nil {
		return s.config.Authorize(shortID)
	}
	return bytes.Equal(shortID[:], s.config.ShortID[:])
}

func (s *Server) addSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	s.sessions[sess.sid] = sess
}

func (s *Server) getSession(sid [SIDLen]byte) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	sess := s.sessions[sid]
	if sess == nil || sess.closed.Load() {
		return nil
	}
	return sess
}

func (s *Server) deleteSession(sid [SIDLen]byte) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[sid]
	delete(s.sessions, sid)
	return sess
}

func (s *Server) cleanupExpiredLocked(now time.Time) {
	for sid, sess := range s.sessions {
		last := time.Unix(0, sess.lastUsed.Load())
		if now.Sub(last) <= s.sessionTTL {
			continue
		}
		delete(s.sessions, sid)
		sess.close()
	}
}

// reaperLoop periodically expires idle sessions so abandoned ones (client
// gone, no CLOSE) cannot accumulate when overall traffic is bursty or sparse.
// Without it a session whose client vanished without CLOSE lingers (handler
// goroutine + buffered pipe + upstream socket) until the next addSession or
// getSession from another client happens to run cleanupExpiredLocked.
func (s *Server) reaperLoop() {
	t := time.NewTicker(s.sessionReapInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			s.cleanupExpiredLocked(time.Now())
			s.mu.Unlock()
		}
	}
}

// Close stops the background session reaper. Existing sessions are left to
// their TTL or an explicit CLOSE. Safe to call multiple times.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
	})
	return nil
}

func (s *session) touch() {
	s.lastUsed.Store(time.Now().UnixNano())
}

func (s *session) close() {
	if s == nil || s.closed.Swap(true) {
		return
	}
	_ = s.conn.Close()
}

func readNULString(r io.Reader, limit int) (string, error) {
	if limit <= 0 {
		limit = 512
	}
	buf := make([]byte, 0, 64)
	var b [1]byte
	for len(buf) <= limit {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(buf), nil
		}
		buf = append(buf, b[0])
	}
	return "", fmt.Errorf("fragpoc: NUL string exceeds %d bytes", limit)
}

func readNULBytes(p []byte, limit int) (string, error) {
	if limit <= 0 {
		limit = 512
	}
	for i, b := range p {
		if i > limit {
			break
		}
		if b == 0 {
			return string(p[:i]), nil
		}
	}
	return "", fmt.Errorf("fragpoc: NUL string exceeds %d bytes", limit)
}

func durationDefault(v, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return v
}

func intDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
