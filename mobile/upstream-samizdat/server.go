package samizdat

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/samizdat/bbcr"
	"golang.org/x/net/http2"
)

// ErrServerClosed is the cause set on the server's context when Close is called.
var ErrServerClosed = errors.New("server closed")

// Server accepts Samizdat connections, authenticates them via Reality-style
// auth in the TLS ClientHello, and proxies authenticated HTTP/2 CONNECT
// tunnels. Non-authenticated connections are transparently proxied to the
// masquerade domain at the TCP level.
type Server struct {
	config       ServerConfig
	serverPubKey []byte

	// Cached TLS certificate - loaded once at NewServer so the auth-success
	// handshake does not do a disk read on the hot path (timing distinguisher
	// fix per audit finding T5). nil on parse error (server refuses to boot).
	cachedCert *tls.Certificate

	// Shaper + fragmenter wire P0.1 record fragmentation into server-side
	// response writes. P0.4 removes per-record jitter from this path.
	shaper       *Shaper
	fragmenter   *RecordFragmenter
	bbcrSessions *bbcr.SessionManager

	// Replay-protection: sliding window of recently-seen SessionID nonces
	// (auth T5 finding - captured ClientHellos could be replayed forever).
	replayGuard *replayGuard

	listenerMu sync.Mutex
	listener   net.Listener
	masquerade *Masquerade
	ctx        context.Context
	cancel     context.CancelCauseFunc
	wg         sync.WaitGroup

	debugMu       sync.Mutex
	debugListener net.Listener
	debugServer   *http.Server
}

// NewServer creates a new Samizdat server.
func NewServer(config ServerConfig) (*Server, error) {
	config.applyDefaults()

	if len(config.PrivateKey) != 32 {
		return nil, fmt.Errorf("PrivateKey must be exactly 32 bytes, got %d", len(config.PrivateKey))
	}
	if len(config.ShortIDs) == 0 {
		return nil, fmt.Errorf("at least one ShortID is required")
	}
	if config.Handler == nil {
		return nil, fmt.Errorf("Handler is required")
	}

	_, serverPubKey, err := derivePublicKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("deriving server public key: %w", err)
	}

	// Pre-load cert so auth-success path does not pay a disk read.
	var cached *tls.Certificate
	if len(config.CertPEM) > 0 && len(config.KeyPEM) > 0 {
		cert, cerr := tls.X509KeyPair(config.CertPEM, config.KeyPEM)
		if cerr != nil {
			return nil, fmt.Errorf("loading TLS certificate: %w", cerr)
		}
		cached = &cert
	}

	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		config:       config,
		serverPubKey: serverPubKey,
		cachedCert:   cached,
		shaper:       NewShaper(false, 0),
		fragmenter:   NewRecordFragmenter(config.RecordFragmentation),
		bbcrSessions: bbcr.NewSessionManager(bbcr.SessionManagerConfig{MaxSessionsPerIdentity: config.BBCRMaxSessionsPerIdentity, MaxStreamsPerSession: config.BBCRMaxStreamsPerSession, IdleTimeout: config.BBCRSessionIdleTimeout}),
		replayGuard:  newReplayGuard(config.ReplayWindow),
		ctx:          ctx,
		cancel:       cancel,
	}

	if config.MasqueradeDomain != "" {
		s.masquerade = NewMasquerade(
			config.MasqueradeDomain,
			config.MasqueradeAddr,
			config.MasqueradeIdleTimeout,
			config.MasqueradeMaxDuration,
		)
	}

	if config.Debug {
		if err := s.startDebugExpvar(); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// logf is a debug-gated wrapper around log.Printf. Production servers run
// with Debug=false so that CONNECT destinations, drain transitions, and
// recovered-panic traces never make it to disk - those logs are a forensic
// goldmine and a side channel that differentiates the authenticated path
// from the masquerade path.
func (s *Server) logf(format string, args ...any) {
	if s.config.Debug {
		log.Printf(format, args...)
	}
}

func (s *Server) startDebugExpvar() error {
	initReplayExpvars()
	addr := s.config.DebugListenAddr
	if addr == "" {
		addr = "127.0.0.1:6060"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("debug expvar listen on %s: %w", addr, err)
	}
	srv := &http.Server{Handler: http.DefaultServeMux}
	s.debugMu.Lock()
	s.debugListener = ln
	s.debugServer = srv
	s.debugMu.Unlock()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logf("[samizdat] debug expvar server: %v", err)
		}
	}()
	return nil
}

func (s *Server) debugAddr() net.Addr {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	if s.debugListener == nil {
		return nil
	}
	return s.debugListener.Addr()
}

// ListenAndServe creates a TCP listener on the configured ListenAddr.
func (s *Server) ListenAndServe() error {
	if s.config.ListenAddr == "" {
		return fmt.Errorf("ListenAddr is required")
	}
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.config.ListenAddr, err)
	}
	return s.Serve(ln)
}

// Serve accepts connections on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	s.listenerMu.Lock()
	s.listener = ln
	s.listenerMu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				return fmt.Errorf("accepting connection: %w", err)
			}
		}

		if err := setAcceptedConnDelayedAck(conn); err != nil {
			s.logf("setting TCP delayed ACK on accepted connection: %v", err)
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

// Close shuts down the server.
func (s *Server) Close() error {
	s.cancel(ErrServerClosed)
	s.listenerMu.Lock()
	ln := s.listener
	s.listenerMu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	s.debugMu.Lock()
	debugServer := s.debugServer
	s.debugMu.Unlock()
	if debugServer != nil {
		if derr := debugServer.Close(); err == nil && derr != nil && !errors.Is(derr, http.ErrServerClosed) {
			err = derr
		}
	}
	s.wg.Wait()
	return err
}

// Addr returns the server's listen address.
func (s *Server) Addr() net.Addr {
	s.listenerMu.Lock()
	ln := s.listener
	s.listenerMu.Unlock()
	if ln != nil {
		return ln.Addr()
	}
	return nil
}

// handleConnection processes a new TCP connection:
// 1. Read the ClientHello (buffer raw bytes)
// 2. Attempt Samizdat auth verification
// 3. If auth passes: complete TLS handshake, enter H2 proxy mode
// 4. If auth fails or replayed: masquerade (forward to real domain)
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	clientHelloRecord, handshakeMsg, err := readClientHelloRecord(conn)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	sessionID, err := ExtractSessionID(handshakeMsg)
	if err != nil {
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	keyShareExt, ok := extractSamizdatKeyShareFromClientHello(handshakeMsg)
	if !ok {
		s.logf("[samizdat] missing or malformed P0.3 keyshare extension")
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	if len(sessionID) != sessionIDLen {
		s.doMasquerade(conn, clientHelloRecord)
		return
	}
	var shortID [shortIDLen]byte
	copy(shortID[:], sessionID[:shortIDLen])
	if !shortIDAllowed(shortID, s.config.ShortIDs) {
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	psk, ephPub, err := DerivePSKFromExtension(s.config.PrivateKey, keyShareExt, shortID)
	if err != nil {
		s.logf("[samizdat] deriving P0.3 PSK failed: %v", err)
		s.doMasquerade(conn, clientHelloRecord)
		return
	}
	verifiedShortID, authenticated, err := VerifySessionIDv1(sessionID, psk, ephPub[:], s.config.ShortIDs)
	if err != nil || !authenticated {
		s.logf("[samizdat] P0.3 SessionID verification failed: %v", err)
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	// Replay check: reject duplicate SessionID+ephemeral-public-key tuples within the replay window.
	if s.replayGuard != nil {
		digest := sha256.New()
		digest.Write(sessionID)
		digest.Write(ephPub[:])
		var replayKey [replayKeyLen]byte
		copy(replayKey[:], digest.Sum(nil)[:replayKeyLen])
		if !s.replayGuard.checkV1(replayKey) {
			s.doMasquerade(conn, clientHelloRecord)
			return
		}
	}

	s.handleAuthenticated(conn, clientHelloRecord, verifiedShortID)
}

// extractSamizdatKeyShareFromClientHello returns the full P0.3 samizdat_keyshare
// extension wire image from a TLS ClientHello. Absent, malformed, or unsupported
// extensions all return false so callers can uniformly fork to masquerade.
func extractSamizdatKeyShareFromClientHello(clientHello []byte) ([]byte, bool) {
	ext, err := ExtractSamizdatKeyShareExtension(clientHello)
	if err != nil {
		return nil, false
	}
	return ext, true
}

// doMasquerade forwards the connection to the real masquerade domain.
func (s *Server) doMasquerade(conn net.Conn, clientHelloRecord []byte) {
	if s.masquerade == nil {
		return
	}
	s.masquerade.ProxyConnection(conn, clientHelloRecord)
}

// shadowDialOrigin absorbs the masquerade origin TCP dial RTT on the
// authenticated path so active probes cannot distinguish auth-success from
// auth-fail purely by first-response timing. Dial failures are intentionally
// ignored: legitimate users must still proceed to the server TLS handshake
// when the cover origin is transiently unreachable, so the shadow dial is
// capped even if the masquerade dial timeout is larger.
func (s *Server) shadowDialOrigin(ctx context.Context) {
	m := s.masquerade
	if m == nil {
		return
	}
	addr := m.OriginAddr
	if addr == "" {
		if m.OriginDomain == "" {
			return
		}
		addr = net.JoinHostPort(m.OriginDomain, "443")
	}
	if addr == "" {
		return
	}
	timeout := m.DialTimeout
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	_ = conn.Close()
}

// handleAuthenticated completes the TLS handshake with the authenticated
// client and serves HTTP/2 CONNECT requests.
func (s *Server) handleAuthenticated(conn net.Conn, clientHelloRecord []byte, identity [8]byte) {
	replayConn := newReplayConn(conn, clientHelloRecord)

	if s.cachedCert == nil {
		return
	}
	if s.masquerade != nil {
		s.shadowDialOrigin(s.ctx)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*s.cachedCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	}

	tlsConn := tls.Server(replayConn, tlsConfig)
	if err := tlsConn.HandshakeContext(s.ctx); err != nil {
		tlsConn.Close()
		return
	}

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return
	}

	s.serveH2(tlsConn, identity)
}

// serveH2 serves HTTP/2 over the authenticated TLS connection.
func (s *Server) serveH2(tlsConn net.Conn, identity [8]byte) {
	h2Server := &http2.Server{
		MaxConcurrentStreams: uint32(s.config.MaxConcurrentStreams),
	}
	effectiveThreshold := randomizedBytesThreshold(s.config.BytesPerFlowThreshold, s.config.BytesThresholdJitter)
	if s.config.EnableBBCR != nil && *s.config.EnableBBCR {
		effectiveThreshold = math.MaxInt64
	}
	flow := &h2Transport{
		tlsConn:            tlsConn,
		maxStreams:         s.config.MaxConcurrentStreams,
		effectiveThreshold: effectiveThreshold,
		drainTimeout:       s.config.DrainTimeout,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flow.isDraining() {
			http.Error(w, "connection draining", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodConnect {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.Host == bbcrSessionAuthority {
			if s.config.EnableBBCR == nil || !*s.config.EnableBBCR {
				http.Error(w, "BBCR disabled", http.StatusNotFound)
				return
			}
			s.serveBBCRConnect(w, r, identity)
			return
		}
		if s.config.EnableBBCR != nil && *s.config.EnableBBCR {
			http.Error(w, "legacy CONNECT disabled", http.StatusNotFound)
			return
		}

		destination := r.Host
		if destination == "" {
			http.Error(w, "No destination", http.StatusBadRequest)
			return
		}

		s.logf("[samizdat] legacy CONNECT: handler started")

		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}

		body := r.Body
		sr := &syncReader{r: body}

		streamConn := &serverStreamConn{
			reader:     io.NopCloser(sr),
			writer:     flushWriter{w: w, flusher: flusher},
			shaper:     s.shaper,
			fragmenter: s.fragmenter,
			debug:      s.config.Debug,
		}

		defer streamConn.shutdown()

		s.config.Handler(r.Context(), streamConn, destination)

		s.logf("[samizdat] legacy CONNECT: handler returned, starting drain")

		drainDone := make(chan struct{})
		go func() {
			n, err := io.Copy(io.Discard, sr)
			s.logf("[samizdat] legacy CONNECT: drain finished, n=%d, err=%v", n, err)
			close(drainDone)
		}()
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-drainDone:
			timer.Stop()
			s.logf("[samizdat] legacy CONNECT: drain completed, handler returning cleanly")
		case <-timer.C:
			s.logf("[samizdat] legacy CONNECT: drain timeout, closing body")
			body.Close()
			<-drainDone
		}
	})

	s.logf("[samizdat] serveH2: starting ServeConn")
	h2Server.ServeConn(flow.wrapServerConn(tlsConn), &http2.ServeConnOpts{
		Handler: handler,
	})
	s.logf("[samizdat] serveH2: ServeConn returned")
}

// readClientHelloRecord reads a complete TLS record from the connection.
func readClientHelloRecord(conn net.Conn) ([]byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, fmt.Errorf("reading TLS record header: %w", err)
	}

	if header[0] != 22 {
		return nil, nil, fmt.Errorf("expected handshake record (type 22), got type %d", header[0])
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 {
		return nil, nil, fmt.Errorf("TLS record too large: %d", recordLen)
	}

	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, nil, fmt.Errorf("reading TLS record payload: %w", err)
	}

	record := make([]byte, 5+recordLen)
	copy(record[:5], header)
	copy(record[5:], payload)

	return record, payload, nil
}

// replayConn wraps a net.Conn and prepends buffered data before reading
// from the real connection.
type replayConn struct {
	net.Conn
	buf    []byte
	offset int
}

func newReplayConn(conn net.Conn, data []byte) *replayConn {
	return &replayConn{
		Conn: conn,
		buf:  data,
	}
}

func (rc *replayConn) Read(b []byte) (int, error) {
	if rc.offset < len(rc.buf) {
		n := copy(b, rc.buf[rc.offset:])
		rc.offset += n
		return n, nil
	}
	return rc.Conn.Read(b)
}

// serverStreamConn wraps an HTTP/2 stream as a net.Conn for the ConnHandler.
// Writes go through the shaper+fragmenter so server-side responses are
// subject to the same record fragmentation (P0.1) and no per-record jitter (P0.4) as
// the client side.
type serverStreamConn struct {
	reader     io.ReadCloser
	writer     flushWriter
	shaper     *Shaper
	fragmenter *RecordFragmenter
	debug      bool
	closed     atomic.Bool
	mu         sync.Mutex
}

func (sc *serverStreamConn) Read(b []byte) (int, error) {
	if sc.closed.Load() {
		return 0, net.ErrClosed
	}
	return sc.reader.Read(b)
}

func (sc *serverStreamConn) Write(b []byte) (n int, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed.Load() {
		return 0, net.ErrClosed
	}
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if ok && msg == "Write called after Handler finished" {
				if sc.debug {
					log.Printf("[samizdat] recovered expected panic in Write: %v", r)
				}
				sc.closed.Store(true)
				n = 0
				err = net.ErrClosed
				return
			}
			if sc.debug {
				log.Printf("[samizdat] unexpected panic in Write: %v", r)
			}
			panic(r)
		}
	}()

	// Route through shaper+fragmenter so outer TLS records stay small and
	// fragmented without per-record jitter - P0.1 and P0.4 wired on the server side.
	if sc.shaper != nil {
		n, err = sc.shaper.FragmentWrite(&flushWriterWrapper{fw: sc.writer}, sc.fragmenter, b)
	} else {
		n, err = sc.writer.Write(b)
		if err == nil {
			sc.writer.Flush()
		}
	}
	return n, err
}

// flushWriterWrapper ensures each fragment is flushed to the H2 framer as
// its own DATA frame.
type flushWriterWrapper struct {
	fw flushWriter
}

func (w *flushWriterWrapper) Write(p []byte) (int, error) {
	n, err := w.fw.Write(p)
	if err == nil {
		w.fw.Flush()
	}
	return n, err
}

func (sc *serverStreamConn) Close() error {
	sc.closed.Store(true)
	return nil
}

func (sc *serverStreamConn) shutdown() {
	sc.mu.Lock()
	sc.closed.Store(true)
	sc.mu.Unlock()
}

func (sc *serverStreamConn) CloseWrite() error {
	return nil
}

func (sc *serverStreamConn) LocalAddr() net.Addr                { return &streamAddr{"tcp", "server"} }
func (sc *serverStreamConn) RemoteAddr() net.Addr               { return &streamAddr{"tcp", "client"} }
func (sc *serverStreamConn) SetDeadline(t time.Time) error      { return nil }
func (sc *serverStreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (sc *serverStreamConn) SetWriteDeadline(t time.Time) error { return nil }

// syncReader serializes concurrent reads with a mutex.
type syncReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (sr *syncReader) Read(b []byte) (int, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.r.Read(b)
}

// flushWriter wraps an http.ResponseWriter with a Flusher.
type flushWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (fw flushWriter) Write(b []byte) (int, error) {
	return fw.w.Write(b)
}

func (fw flushWriter) Flush() {
	if fw.flusher != nil {
		fw.flusher.Flush()
	}
}

// defaultConnHandler is a simple handler that dials the destination and
// proxies data bidirectionally.
func defaultConnHandler(ctx context.Context, conn net.Conn, destination string) {
	defer conn.Close()

	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		port = "443"
	}
	_ = host

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
	}()

	wg.Wait()
}

var (
	_ net.Conn = (*serverStreamConn)(nil)
	_ net.Conn = (*replayConn)(nil)
)
