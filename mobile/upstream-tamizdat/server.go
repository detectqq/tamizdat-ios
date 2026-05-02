package tamizdat

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

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
	shaper     *Shaper
	fragmenter *RecordFragmenter

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

	// MED-4: track in-flight TCP connections so Server.Close can actively
	// terminate them. Without this, h2Server.ServeConn parks on tlsConn.Read
	// and wg.Wait() blocks forever, breaking systemd graceful-shutdown.
	activeConns sync.Map // map[net.Conn]struct{}

	// Per-IP rate-limiter on masquerade forwards (compass v2 §3.11 DoS protection).
	masqLimiter *masqueradeRateLimiter
	realtime    *RealtimeController

	shortIDPool     *shortIDPool
	coverConfigJSON []byte
}

// NewServer creates a new Samizdat server.
func NewServer(config ServerConfig) (*Server, error) {
	config.applyDefaults()

	if len(config.PrivateKey) != 32 {
		return nil, fmt.Errorf("PrivateKey must be exactly 32 bytes, got %d", len(config.PrivateKey))
	}
	var zeroShortID [8]byte
	if config.MasterShortID == zeroShortID {
		return nil, fmt.Errorf("MasterShortID is required")
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
		replayGuard:  newReplayGuard(config.ReplayWindow),
		ctx:          ctx,
		cancel:       cancel,
		realtime:     newRealtimeController(),
		shortIDPool:  newShortIDPool(config.MasterShortID, config.EpochGraceWindow),
	}

	// Aparecium audit fix: pad cert chain to ~3.5 KB extra so encrypted
	// Certificate flight in TLS 1.3 handshake matches the size of a real
	// CDN cert chain (e.g. ok.ru â GlobalSign chain ~4 KB DER). Without
	// padding our self-signed single cert (~1 KB) gives a passive size-based
	// detector signal even though TLS 1.3 encrypts cert content.
	if cached != nil && len(cached.Certificate) > 0 {
		padded, perr := padCertChain(cached.Certificate, 4200, 3)
		if perr == nil {
			cached.Certificate = padded
		}
		// On padding failure (rsa.GenerateKey error etc.) we silently keep
		// the un-padded chain rather than fail server startup. Detection
		// risk degrades gracefully.
	}

	s.masqLimiter = newMasqueradeRateLimiter()

	if err := s.initCoverConfig(config); err != nil {
		return nil, err
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

func (s *Server) initCoverConfig(config ServerConfig) error {
	if config.CoverConfigPath == "" {
		s.coverConfigJSON = []byte(`{"version":1}`)
		return nil
	}
	if config.CoverConfigPreviousPath != "" {
		previous, err := LoadCoverConfigWithMasquerade(config.CoverConfigPreviousPath, config.MasqueradePool)
		if err != nil {
			return fmt.Errorf("load previous cover config: %w", err)
		}
		if previous.EpochKey != "" && previous.ShortIDPoolSize > 0 {
			s.shortIDPool.Rotate(previous.EpochKey, previous.ShortIDPoolSize)
		}
	}
	bundle, err := LoadCoverConfigWithMasquerade(config.CoverConfigPath, config.MasqueradePool)
	if err != nil {
		return fmt.Errorf("load cover config: %w", err)
	}
	wire, err := bundle.MarshalForWire()
	if err != nil {
		return err
	}
	s.coverConfigJSON = wire
	if bundle.EpochKey != "" && bundle.ShortIDPoolSize > 0 {
		s.shortIDPool.Rotate(bundle.EpochKey, bundle.ShortIDPoolSize)
	}
	return nil
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
	initTelemetry()
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
			s.logf("[tamizdat] debug expvar server: %v", err)
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
	// MED-4: actively terminate in-flight TCP connections so handleConnection
	// goroutines unblock from Read and wg.Wait() can return. Without this,
	// SIGINT-driven shutdown hangs until every TCP peer FINs (or never).
	s.activeConns.Range(func(k, _ any) bool {
		if c, ok := k.(net.Conn); ok {
			_ = c.Close()
		}
		return true
	})
	if s.masqLimiter != nil {
		s.masqLimiter.close()
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
	// MED-4: register this conn so Close() can terminate it.
	s.activeConns.Store(conn, struct{}{})
	defer s.activeConns.Delete(conn)
	safeIntAdd(connectTotal, 1)
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

	// Standard TLS-1.3 key_share auth (compass v2 §5.1 fully migrated; legacy
	// 0xFE0C extension path removed in compass v3 cleanup -- 24h+ soak passed).
	ephPub, err := ExtractX25519FromKeyShare(handshakeMsg)
	if err != nil {
		s.logf("[tamizdat] ephemeral pubkey extraction failed: %v", err)
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	if len(sessionID) != sessionIDLen {
		s.doMasquerade(conn, clientHelloRecord)
		return
	}
	var shortID [shortIDLen]byte
	copy(shortID[:], sessionID[:shortIDLen])

	// Timing-oracle hardening: derive and HMAC-check using the candidate
	// shortID before consulting shortIDPool.Accept. Unknown-shortID probes and
	// known-shortID/bad-tag probes both pay the same expensive auth path.
	psk, err := DeriveServerPSK(s.config.PrivateKey, ephPub[:], shortID)
	if err != nil {
		s.logf("[tamizdat] deriving PSK failed: %v", err)
		s.doMasquerade(conn, clientHelloRecord)
		return
	}
	verifiedShortID, authenticated, err := VerifySessionIDv1(sessionID, psk, ephPub[:], [][shortIDLen]byte{shortID})
	acceptedShortID := s.shortIDPool != nil && s.shortIDPool.Accept(shortID)
	if err != nil || !authenticated || !acceptedShortID {
		s.logf("[tamizdat] P0.3 SessionID verification failed: %v", err)
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
			safeIntAdd(connectReplay, 1)
			s.doMasquerade(conn, clientHelloRecord)
			return
		}
	}

	safeIntAdd(connectAuthOK, 1)
	s.handleAuthenticated(conn, clientHelloRecord, verifiedShortID)
}

// doMasquerade forwards the connection to the real masquerade domain.
func (s *Server) doMasquerade(conn net.Conn, clientHelloRecord []byte) {
	if s.masquerade == nil {
		return
	}
	// compass v2 §3.11: per-IP rate-limit on masquerade forwards.
	if !s.masqLimiter.allow(extractRemoteIP(conn)) {
		safeIntAdd(masqRateLimited, 1)
		return
	}
	safeIntAdd(connectMasquerade, 1)
	// Cover-SNI rotation (compass P1.1): parse SNI from buffered ClientHello,
	// look up matching origin in MasqueradePool. Empty/unknown SNI → default.
	originDomain := ""
	if len(s.config.MasqueradePool) > 0 {
		// clientHelloRecord includes 5-byte TLS record header; strip it for handshake parser.
		if len(clientHelloRecord) > 5 {
			if sni, err := parseSNIFromClientHello(clientHelloRecord[5:]); err == nil && sni != "" {
				if origin, ok := s.config.MasqueradePool[sni]; ok && origin != "" {
					originDomain = origin
				}
			}
		}
	}
	s.masquerade.ProxyConnectionWithOrigin(conn, clientHelloRecord, originDomain)
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
		// Aparecium NST mitigation v2 (compass deep-research v2 finding):
		// Earlier probe with OpenSSL ClientHello to ok.ru returned 0 NST, but
		// re-probe with real Chrome ClientHello (utls.HelloChrome_Auto) returns
		// ~40 bytes post-handshake = 1 small NST. Since samizdat uses utls
		// Chrome by default, the matching origin-pattern is Go's default 1 NST,
		// not zero. Leave SessionTicketsDisabled=false (default) so Go emits 1
		// NewSessionTicket after ClientFinished -- closes the Aparecium PoC's
		// "no NST after ClientFinished" detector.
		SessionTicketsDisabled: false,
	}

	tlsConn := tls.Server(replayConn, tlsConfig)
	hsStart := time.Now()
	if err := tlsConn.HandshakeContext(s.ctx); err != nil {
		tlsConn.Close()
		return
	}

	handshakeDurationNanosSum.Add(int64(time.Since(hsStart)))
	handshakeDurationNanosCount.Add(1)
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
		// OPT-2: server-side H2 PING keepalive. golang.org/x/net/http2 server
		// sends PING after IdleTimeout of inactivity; if no PONG within
		// PingTimeout, server tears down the connection. Defends symmetrically
		// against NAT-table eviction and detects half-open connections.
		IdleTimeout:     60 * time.Second,
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     10 * time.Second,
		// OPT-1: per-stream initial upload window so client uploads aren't
		// capped at default 64 KB. Also bump connection-level via
		// MaxUploadBufferPerConnection. Matches NaiveProxy/Hysteria tuning.
		MaxUploadBufferPerConnection: 16 << 20, // 16 MiB
		MaxUploadBufferPerStream:     4 << 20,  //  4 MiB
		MaxReadFrameSize:             1 << 20,  //  1 MiB
	}
	flow := &h2Transport{
		tlsConn:      tlsConn,
		maxStreams:   s.config.MaxConcurrentStreams,
		drainTimeout: s.config.DrainTimeout,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.Host == configAuthority {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(s.coverConfigJSON)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}

		destination := r.Host
		if destination == "" {
			http.Error(w, "No destination", http.StatusBadRequest)
			return
		}

		// Branch on Samizdat-Protocol header to route UDP-over-CONNECT through
		// the dedicated handler (udp_server.go). Empty / "tcp/1" is the default
		// TCP CONNECT path. The realtime classifier is consulted here, after
		// CONNECT authority parse and before stream handling.
		proto := r.Header.Get(SamizdatProtocolHeader)
		network := "tcp"
		if proto == SamizdatProtocolUDP {
			network = "udp"
		}
		class := TrafficBulk
		if s.realtime != nil {
			// Server-side first-RTT realtime still uses the accepted socket's
			// delayed-ACK posture: class is only knowable after CONNECT parsing,
			// so V2 leaves post-CONNECT TCP_QUICKACK flips out of scope.
			class = s.realtime.Detector.ClassifyOpen(NewFlowMeta(network, destination))
		}

		switch proto {
		case "", "tcp/1":
			// fallthrough to TCP CONNECT handler below
		case SamizdatProtocolUDP:
			s.handleUDPCONNECT(w, r, destination)
			return
		default:
			http.Error(w, "unsupported tamizdat-protocol", http.StatusBadRequest)
			return
		}

		s.logf("[tamizdat] legacy CONNECT: handler started")

		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}

		body := r.Body
		sr := &syncReader{r: body}

		streamConn := &serverStreamConn{
			reader:       io.NopCloser(sr),
			writer:       flushWriter{w: w, flusher: flusher},
			shaper:       s.shaper,
			fragmenter:   s.fragmenter,
			debug:        s.config.Debug,
			trafficClass: class,
		}

		defer streamConn.shutdown()

		s.config.Handler(r.Context(), streamConn, destination)

		s.logf("[tamizdat] legacy CONNECT: handler returned, starting drain")

		drainDone := make(chan struct{})
		go func() {
			n, err := io.Copy(io.Discard, sr)
			s.logf("[tamizdat] legacy CONNECT: drain finished, n=%d, err=%v", n, err)
			close(drainDone)
		}()
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-drainDone:
			timer.Stop()
			s.logf("[tamizdat] legacy CONNECT: drain completed, handler returning cleanly")
		case <-timer.C:
			s.logf("[tamizdat] legacy CONNECT: drain timeout, closing body")
			body.Close()
			<-drainDone
		}
	})

	s.logf("[tamizdat] serveH2: starting ServeConn")
	h2Server.ServeConn(flow.wrapServerConn(tlsConn), &http2.ServeConnOpts{
		Handler: handler,
	})
	s.logf("[tamizdat] serveH2: ServeConn returned")
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
	reader       io.ReadCloser
	writer       flushWriter
	shaper       *Shaper
	fragmenter   *RecordFragmenter
	debug        bool
	trafficClass TrafficClass
	closed       atomic.Bool
	mu           sync.Mutex

	// HIGH-2: deadline enforcement to satisfy net.Conn contract.
	// rd / wd store the deadline as Unix nanos (0 = no deadline). Read/Write
	// check before blocking; rdTimer/wdTimer fire reader.Close() when the
	// deadline elapses while a Read is parked, which propagates io.EOF to
	// the blocked goroutine.
	rd      atomic.Int64
	wd      atomic.Int64
	dlMu    sync.Mutex
	rdTimer *time.Timer
	wdTimer *time.Timer
}

func (sc *serverStreamConn) Read(b []byte) (int, error) {
	if sc.closed.Load() {
		return 0, net.ErrClosed
	}
	if t := sc.rd.Load(); t != 0 && t <= time.Now().UnixNano() {
		return 0, os.ErrDeadlineExceeded
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
					log.Printf("[tamizdat] recovered expected panic in Write: %v", r)
				}
				sc.closed.Store(true)
				n = 0
				err = net.ErrClosed
				return
			}
			if sc.debug {
				log.Printf("[tamizdat] unexpected panic in Write: %v", r)
			}
			panic(r)
		}
	}()

	if sc.trafficClass == TrafficRealtime {
		n, err = sc.writer.Write(b)
		if err == nil {
			sc.writer.Flush()
		}
		return n, err
	}

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

func (sc *serverStreamConn) LocalAddr() net.Addr  { return &streamAddr{"tcp", "server"} }
func (sc *serverStreamConn) RemoteAddr() net.Addr { return &streamAddr{"tcp", "client"} }

// SetDeadline sets both read and write deadlines. Implements net.Conn contract:
// blocked Read/Write returns os.ErrDeadlineExceeded after t; t.IsZero() clears.
func (sc *serverStreamConn) SetDeadline(t time.Time) error {
	_ = sc.SetReadDeadline(t)
	_ = sc.SetWriteDeadline(t)
	return nil
}

func (sc *serverStreamConn) SetReadDeadline(t time.Time) error {
	sc.dlMu.Lock()
	defer sc.dlMu.Unlock()
	if sc.rdTimer != nil {
		sc.rdTimer.Stop()
		sc.rdTimer = nil
	}
	if t.IsZero() {
		sc.rd.Store(0)
		return nil
	}
	sc.rd.Store(t.UnixNano())
	d := time.Until(t)
	if d <= 0 {
		// Already past: close reader so any in-flight Read returns immediately.
		_ = sc.reader.Close()
		return nil
	}
	sc.rdTimer = time.AfterFunc(d, func() {
		// Re-check the stored deadline in case it was reset to a later time
		// before the timer fired. If it was, do nothing.
		now := time.Now().UnixNano()
		if cur := sc.rd.Load(); cur != 0 && cur <= now {
			_ = sc.reader.Close()
		}
	})
	return nil
}

func (sc *serverStreamConn) SetWriteDeadline(t time.Time) error {
	sc.dlMu.Lock()
	defer sc.dlMu.Unlock()
	if sc.wdTimer != nil {
		sc.wdTimer.Stop()
		sc.wdTimer = nil
	}
	if t.IsZero() {
		sc.wd.Store(0)
		return nil
	}
	sc.wd.Store(t.UnixNano())
	d := time.Until(t)
	if d <= 0 {
		// Already past: shut down the write side so in-flight Writes fail fast.
		_ = sc.shutdownWriteSide()
		return nil
	}
	sc.wdTimer = time.AfterFunc(d, func() {
		now := time.Now().UnixNano()
		if cur := sc.wd.Load(); cur != 0 && cur <= now {
			_ = sc.shutdownWriteSide()
		}
	})
	return nil
}

// shutdownWriteSide is a best-effort: closes the underlying reader (which
// drives the H2 stream lifecycle); the H2 framer will propagate RST_STREAM,
// failing any subsequent Write.
func (sc *serverStreamConn) shutdownWriteSide() error {
	if sc.closed.Swap(true) {
		return nil
	}
	return sc.reader.Close()
}

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
	safeIntAdd(tunnelsTCPOpened, 1)
	defer safeIntAdd(tunnelsTCPClosed, 1)
	var flowBytes int64
	defer func() { observeFlowBytes(flowBytes) }()

	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		port = "443"
	}

	// CRIT-0: validate destination and dial the resolved IP directly. Defeats
	// SSRF (RFC1918/loopback/cloud-metadata/CGNAT) and the DNS-rebinding TOCTOU
	// window between validation and net.Dial's own resolver.
	target, err := ResolveAndValidateDestination(ctx, host, port)
	if err != nil {
		safeIntAdd(ssrfRejectedTCP, 1)
		return
	}

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, conn)
		atomic.AddInt64(&flowBytes, n)
		bytesClientToTarget.Add(n)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, targetConn)
		atomic.AddInt64(&flowBytes, n)
		bytesTargetToClient.Add(n)
		// HIGH-6: when target sends EOF, propagate write-close to the H2 stream
		// so the client's blocking Read(s) on its side can wake up cleanly.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
}

var (
	_ net.Conn = (*serverStreamConn)(nil)
	_ net.Conn = (*replayConn)(nil)
)
