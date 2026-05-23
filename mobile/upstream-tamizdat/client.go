package tamizdat

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

var setClientTCPQuickAck = setTCPQuickAck

// pickServerNameExcluding returns a random SNI from the pool, biased away
// from any SNI in `exclude`. Used to guarantee that a freshly-spawned lite
// transport picks a different cover SNI than the active bulk transport so
// the TSPU #546 counter (src_IP, SNI, JA3) for any single SNI stays at 1.
//
// If filtering yields an empty candidate set (pool exhausted by excludes),
// falls back to the unfiltered weighted pick — the safety property is
// best-effort, not absolute.
func (c *Client) pickServerNameExcluding(exclude []string) string {
	if len(exclude) == 0 {
		return c.pickServerName()
	}
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, e := range exclude {
		if e != "" {
			excludeSet[e] = struct{}{}
		}
	}
	if pushed := c.serverPushedSNIPool.Load(); pushed != nil && len(*pushed) > 0 {
		primary := c.config.PrimarySNI
		if primary == "" {
			primary = c.config.ServerName
		}
		entries := []SNIEntry{}
		if _, skip := excludeSet[primary]; !skip {
			entries = append(entries, SNIEntry{SNI: primary, Weight: 100})
		}
		for _, e := range *pushed {
			if e.SNI == "" {
				continue
			}
			if _, skip := excludeSet[e.SNI]; skip {
				continue
			}
			if len(entries) > 0 && entries[0].SNI == primary && e.SNI == primary {
				if e.Weight > entries[0].Weight {
					entries[0].Weight = e.Weight
				}
				continue
			}
			entries = append(entries, e)
		}
		if len(entries) > 0 {
			if picked := pickWeightedSNI(entries); picked != "" {
				return picked
			}
		}
	}
	pool := c.config.ServerNames
	if len(pool) == 0 {
		return c.pickServerName()
	}
	filtered := pool[:0:0]
	for _, s := range pool {
		if _, skip := excludeSet[s]; skip {
			continue
		}
		filtered = append(filtered, s)
	}
	if len(filtered) == 0 {
		return c.pickServerName()
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	var idx [8]byte
	_, _ = rand.Read(idx[:])
	i := int(binary.BigEndian.Uint64(idx[:])>>1) % len(filtered)
	return filtered[i]
}

// pickServerName returns a randomly-chosen SNI from the configured pool.
// Falls back to legacy single ServerName when no pool is configured.
// Per-transport rotation breaks the "all clients of one IP share one SNI"
// behavioural correlation flagged by compass P1.1.
func (c *Client) pickServerName() string {
	if pushed := c.serverPushedSNIPool.Load(); pushed != nil && len(*pushed) > 0 {
		primary := c.config.PrimarySNI
		if primary == "" {
			primary = c.config.ServerName
		}
		// Per spec §3.B (clarified 2026-05-01): if bundle has primary's sni, use max(its weight, 100); else insert primary at weight 100; append other bundle entries unchanged.
		entries := []SNIEntry{{SNI: primary, Weight: 100}}
		for _, e := range *pushed {
			if e.SNI == "" {
				continue
			}
			if e.SNI == primary {
				if e.Weight > entries[0].Weight {
					entries[0].Weight = e.Weight
				}
				continue
			}
			entries = append(entries, e)
		}
		if picked := pickWeightedSNI(entries); picked != "" {
			return picked
		}
	}
	pool := c.config.ServerNames
	if len(pool) == 0 {
		if c.config.PrimarySNI != "" {
			return c.config.PrimarySNI
		}
		return c.config.ServerName
	}
	if len(pool) == 1 {
		return pool[0]
	}
	var idx [8]byte
	_, _ = rand.Read(idx[:])
	i := int(binary.BigEndian.Uint64(idx[:])>>1) % len(pool)
	return pool[i]
}

// pickShortID returns a randomly-chosen shortID from the configured pool. If
// no pool is configured, falls back to the legacy single ShortID. Per-transport
// rotation breaks the "fixed 8-byte SessionID prefix per server IP" signal.
func (c *Client) pickShortID() [8]byte {
	poolPtr := c.derivedShortIDs.Load()
	if poolPtr == nil || len(*poolPtr) == 0 {
		return c.config.MasterShortID
	}
	pool := *poolPtr
	var idx [8]byte
	_, _ = rand.Read(idx[:])
	i := int(binary.BigEndian.Uint64(idx[:])>>1) % (len(pool) + 1) // +1 includes master
	if i == 0 {
		return c.config.MasterShortID
	}
	return pool[i-1]
}

// Client dials connections through a Samizdat server. Multiple calls to
// DialContext share the same underlying TLS+H2 connection via multiplexing.
type Client struct {
	config              ClientConfig
	pool                *connPool
	shaper              *Shaper
	fragmenter          *RecordFragmenter
	fingerprintChooser  *fingerprintRotator
	cover               *coverDriver
	handshakeLimiter    *handshakeLimiter
	realtime            *RealtimeController
	derivedShortIDs     atomic.Pointer[[][8]byte]
	serverPushedSNIPool   atomic.Pointer[[]SNIEntry]
	serverPushedTURNCreds atomic.Pointer[TURNCredsEntry]
	coverCtx              context.Context
	coverCancel         context.CancelFunc
	bundleCtx           context.Context
	bundleCancel        context.CancelFunc
	// v1FlipChan delivers async ShapeMode flips for the V1 single-transport
	// hot path. Audit #6: Promote -> onRealtimeOpen runs on the first RTP
	// packet and previously held pool.mu + did syscalls inline; that delay
	// hits the latency-critical packet. We now signal a goroutine via a
	// buffered chan so the observer returns immediately.
	v1FlipChan          chan ShapeMode
	rttProbe            *rttProbe
	v1FlipDone          chan struct{}
	mu                  sync.Mutex
	closed              bool
}

// NewClient creates a new Samizdat client.
func NewClient(config ClientConfig) (*Client, error) {
	config.applyDefaults()

	if len(config.PublicKey) != 32 {
		return nil, fmt.Errorf("PublicKey must be exactly 32 bytes, got %d", len(config.PublicKey))
	}
	if config.ServerAddr == "" {
		return nil, fmt.Errorf("ServerAddr is required")
	}
	if config.PrimarySNI == "" {
		return nil, fmt.Errorf("PrimarySNI/ServerName is required")
	}
	var zeroShortID [8]byte
	if config.MasterShortID == zeroShortID {
		return nil, fmt.Errorf("MasterShortID/ShortID is required")
	}

	c := &Client{
		config:           config,
		handshakeLimiter: newHandshakeLimiter(),
		realtime:         newRealtimeController(),
	}
	c.bundleCtx, c.bundleCancel = context.WithCancel(context.Background())

	c.shaper = NewShaper(false, 0)
	c.fragmenter = NewRecordFragmenter(config.RecordFragmentation)
	c.fingerprintChooser = newFingerprintRotator(config.Fingerprint)
	// liteSpawnDelay default 3 sec — operator-supplied filter against short
	// STUN probes (analyst #3 recommendation 2026-05-03). Disabled in strict
	// mode (no lite spawn at all under strict).
	liteSpawnDelay := 3 * time.Second
	if config.StrictSingleH2 {
		liteSpawnDelay = 0
	}
	c.pool = newConnPool(config.MaxStreamsPerConn, config.IdleTimeout, config.MinTransports, config.MaxTransports, config.BytesPerTransportSoftCap, config.RotationOverlapAllowance, config.StrictSingleH2, liteSpawnDelay, func(ctx context.Context, class TrafficClass) (*h2Transport, error) {
		return c.createTransport(ctx, class)
	})
	c.pool.setRealtimeController(c.realtime)
	c.realtime.onLastRealtimeClose = func() {
		c.pool.armLiteCloseHysteresis()
		c.pool.resetFirstRealtimeNanos()
	}
	if config.MaxTransports == 1 {
		// V1 path: defer the (potentially slow) pool-wide flip to a worker
		// goroutine so Promote -> Observe never blocks on pool.mu or syscalls.
		c.v1FlipChan = make(chan ShapeMode, 4)
		c.v1FlipDone = make(chan struct{})
		go c.v1FlipWorker()
		// Tier 2.5: V1 valve fires on RTP-stickylocked flow transitions only.
		// onRealtimeOpen still fires on any realtime-class flow (including
		// default-promoted UDP background like NTP/QUIC) — used for hysteresis
		// management ONLY, no shape flip.
		c.realtime.onRealtimeOpen = func() {
			c.pool.cancelLiteCloseHysteresis()
		}
		// Locked-flow callbacks: only proven realtime (RTP-stickylocked) drives
		// the valve. Background UDP no longer flips the pipe.
		c.realtime.onLockedOpen = func() {
			select {
			case c.v1FlipChan <- ShapeLite:
			default:
			}
		}
		c.realtime.onLockedReturnToFull = func() {
			select {
			case c.v1FlipChan <- ShapeFull:
			default:
			}
		}
		// Backstop: even if locked-flow tracking missed a 1->0 (e.g., flow
		// closed without going through Forget cleanly), hysteresis on
		// activeRealtimeCount eventually fires onModeReturnToFull and we
		// re-push ShapeFull. Idempotent.
		c.realtime.onModeReturnToFull = func() {
			select {
			case c.v1FlipChan <- ShapeFull:
			default:
			}
		}
	} else {
		c.realtime.onRealtimeOpen = c.pool.cancelLiteCloseHysteresis
	}

	if config.CoverTrafficEnabled {
		c.coverCtx, c.coverCancel = context.WithCancel(context.Background())
		c.cover = c.startCoverTraffic(c.coverCtx, config.CoverTrafficTargets)
	}

	c.rttProbe = newRTTProbe(c)
	c.rttProbe.start()
	return c, nil
}

// DialContext opens a proxied connection to the destination through the server.
// ShapeMode returns the current transport-wide shape mode of the bulk
// transport. Useful for debug/observability via expvar:
//
//	expvar.Publish("tamizdat_shape_mode", expvar.Func(func() interface{} {
//	    return client.ShapeMode()
//	}))
//
// Returns "ShapeFull" or "ShapeLite". Returns "ShapeFull" if controller is nil.
func (c *Client) ShapeMode() string {
	if c == nil || c.realtime == nil {
		return "ShapeFull"
	}
	return c.realtime.Mode().String()
}

// DisableRealtimeDetector puts the client's realtime classifier into
// no-op mode. ClassifyOpen / Observe early-return TrafficBulk; per-
// packet d.mu acquisition is skipped; cleanupLoop exits gracefully.
// Wire-protocol unaffected — server-side classifier runs independently.
//
// IPA-A7 iOS-local: speedtest-time mutex contention on the global
// detector lock (10000 acq/sec) was the dominant CPU cost on iOS.
// Operator's measurement showed bulk-vs-lite RTT difference of 1 ms
// — no measurable user benefit on this network. Trade the realtime-
// aware shape-flip for a simpler V1+StrictSingleH2 invariant.
func (c *Client) DisableRealtimeDetector() {
	if c == nil || c.realtime == nil || c.realtime.Detector == nil {
		return
	}
	c.realtime.Detector.Disable()
}

// ActiveRealtimeCount returns the live count of realtime-class flows tracked
// by the client's realtime controller. Useful for debug observability.
func (c *Client) ActiveRealtimeCount() int {
	if c == nil || c.realtime == nil {
		return 0
	}
	return c.realtime.ActiveRealtimeCount()
}

// LockedRealtimeCount returns the count of RTP-stickylocked (proven real
// realtime) flows. Distinct from ActiveRealtimeCount which includes
// default-promoted UDP background noise. Drives V1 valve toggle.
func (c *Client) LockedRealtimeCount() int32 {
	if c == nil || c.realtime == nil {
		return 0
	}
	return c.realtime.LockedRealtimeCount()
}

// RealShapeMode returns the actual wire-shape of the bulk transport — what
// outgoing TLS records are really shaped as right now. This is the ground
// truth, not controller-intent. For V1 (single transport) this directly
// reflects whether the valve has flipped.
func (c *Client) RealShapeMode() string {
	if c == nil || c.pool == nil {
		return ""
	}
	return c.pool.BulkTransportShapeMode().String()
}

// LiteTransportAlive reports whether the V2/V3 dedicated lite-class realtime
// transport is currently live. Always 0 for V1 (MaxTransports==1) where there
// is no separate lite truba. Used for variant-aware lamp logic: V1 lights on
// bulk-shape flip, V2/V3 light on this + locked-flow count.
func (c *Client) LiteTransportAlive() int32 {
	if c == nil || c.pool == nil {
		return 0
	}
	if c.pool.LiteTransportAlive() {
		return 1
	}
	return 0
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	class := TrafficBulk
	var flowID uint64
	if c.realtime != nil {
		var token *flowToken
		class, token = c.realtime.Detector.ClassifyOpenWithToken(NewFlowMeta(network, address))
		flowID = c.realtime.OpenWithToken(class, token)
	}
	closeRealtime := func() {
		if c.realtime != nil && flowID != 0 {
			c.realtime.Close(flowID)
		}
	}

	transport, err := c.pool.getTransportForClass(ctx, class)
	if err != nil {
		closeRealtime()
		return nil, fmt.Errorf("getting transport: %w", err)
	}

	conn, err := transport.openTunnel(ctx, address)
	if err != nil {
		transport.releaseStreamSlot()
		closeRealtime()
		return nil, fmt.Errorf("opening tunnel to %s: %w", address, err)
	}

	return wrapRealtimeConn(conn, c.realtime, flowID), nil
}

// dialBulk opens an internal TCP tunnel pinned to the bulk transport class.
// Cover traffic uses this to bypass realtime classification explicitly.
func (c *Client) dialBulk(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("dialBulk supports tcp only, got %q", network)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	transport, err := c.pool.getTransportForClass(ctx, TrafficBulk)
	if err != nil {
		return nil, fmt.Errorf("getting bulk transport: %w", err)
	}
	conn, err := transport.openTunnel(ctx, address)
	if err != nil {
		transport.releaseStreamSlot()
		return nil, fmt.Errorf("opening bulk tunnel to %s: %w", address, err)
	}
	return conn, nil
}

// DialUDP opens a UDP-tunneling stream to the destination through the server.
// Returns a net.PacketConn that frames inner UDP datagrams as length-prefixed
// records over the H2 stream. Single-target: WriteTo addresses other than the
// CONNECT authority are rejected; ReadFrom always returns address as Addr.
func (c *Client) DialUDP(ctx context.Context, address string) (net.PacketConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	class := TrafficBulk
	var flowID uint64
	if c.realtime != nil {
		var token *flowToken
		class, token = c.realtime.Detector.ClassifyOpenWithToken(NewFlowMeta("udp", address))
		flowID = c.realtime.OpenWithToken(class, token)
	}
	closeRealtime := func() {
		if c.realtime != nil && flowID != 0 {
			c.realtime.Close(flowID)
		}
	}

	transport, err := c.pool.getTransportForClass(ctx, class)
	if err != nil {
		closeRealtime()
		return nil, fmt.Errorf("getting transport: %w", err)
	}

	rwc, err := transport.openUDPTunnel(ctx, address, class)
	if err != nil {
		transport.releaseStreamSlot()
		closeRealtime()
		return nil, fmt.Errorf("opening UDP tunnel to %s: %w", address, err)
	}

	if c.realtime != nil && c.realtime.Detector != nil && flowID != 0 {
		if stream, ok := rwc.(*h2StreamRWC); ok {
			c.realtime.Detector.registerMigrationHandle(flowID, &migrationHandle{
				fastCloseFn:           stream.fastClose,
				dstAddr:               address,
				originalTransportLite: transport.class == TrafficRealtime,
				ensureBulkFn: func() error {
					bulkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					bulkTransport, err := c.pool.getTransportForClass(bulkCtx, TrafficBulk)
					if err != nil {
						return err
					}
					bulkTransport.releaseStreamSlot()
					return nil
				},
			})
		}
	}

	target := &streamAddr{network: "udp", address: address}
	pc := newUDPFramedPacketConn(rwc, target)
	return wrapRealtimePacketConn(pc, c.realtime, flowID), nil
}

// Close shuts down all connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.rttProbe != nil {
		c.rttProbe.stop()
	}
	if c.bundleCancel != nil {
		c.bundleCancel()
	}
	if c.coverCancel != nil {
		c.coverCancel()
	}
	if c.cover != nil {
		c.cover.close()
	}
	if c.realtime != nil && c.realtime.Detector != nil {
		c.realtime.Detector.Close()
	}
	if c.v1FlipDone != nil {
		select {
		case <-c.v1FlipDone:
		default:
			close(c.v1FlipDone)
		}
	}
	return c.pool.close()
}

// v1FlipWorker drains v1FlipChan and applies the latest mode to all bulk
// transports asynchronously. Coalesces successive same-mode signals.
func (c *Client) v1FlipWorker() {
	for {
		select {
		case mode := <-c.v1FlipChan:
			// Drain any pending updates — only the latest mode matters.
			for draining := true; draining; {
				select {
				case next := <-c.v1FlipChan:
					mode = next
				default:
					draining = false
				}
			}
			c.pool.flipAllBulkTransports(mode)
		case <-c.v1FlipDone:
			return
		}
	}
}

// createTransport creates a new TLS+H2 connection to the server with
// Reality-style auth embedded in the ClientHello.
func (c *Client) createTransport(ctx context.Context, class TrafficClass) (*h2Transport, error) {
	if c.handshakeLimiter != nil {
		if err := c.handshakeLimiter.Wait(ctx, c.config.ServerAddr); err != nil {
			return nil, err
		}
	}

	var tcpConn net.Conn
	var err error

	if c.config.Dialer != nil {
		tcpConn, err = c.config.Dialer(ctx, "tcp", c.config.ServerAddr)
	} else {
		dialer := &net.Dialer{Timeout: c.config.ConnectTimeout}
		tcpConn, err = dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("TCP dial to %s: %w", c.config.ServerAddr, err)
	}
	if class == TrafficRealtime {
		_ = setClientTCPQuickAck(tcpConn, true)
	}

	var conn net.Conn = tcpConn
	var fragmenter *Fragmenter
	if c.config.TCPFragmentation {
		// #7 adaptive Geneva: bandit picks strategy per server (host:port).
		// Outcome reported below after handshake completes.
		fragmenter = NewFragmenterWithStrategy(tcpConn, true, c.config.ServerAddr, "")
		conn = fragmenter
	}

	var sni string
	if class == TrafficRealtime {
		// Lite transport: avoid the SNI(s) used by the bulk transport(s).
		// Counter (src_IP, SNI, JA3) for any single SNI stays at 1 even
		// under multi-transport (V1 default + lite, or V2/V3).
		sni = c.pickServerNameExcluding(c.pool.activeSNIs())
	} else {
		sni = c.pickServerName()
	}
	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	helloID := c.fingerprintChooser.pick()
	uConn := utls.UClient(conn, tlsConfig, helloID)

	// compass v2 §5.1 Approach A (Reality-style): instead of generating a
	// separate ephemeral X25519 keypair and stuffing the pub into a private
	// extension 0xFE0C, we piggy-back on the X25519 keypair uTLS ALREADY
	// generates for the standard TLS-1.3 key_share extension. Result: zero
	// JA4-fingerprintable extensions appear in our ClientHello.
	if err := uConn.BuildHandshakeState(); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("building uTLS handshake state: %w", err)
	}
	ksk := uConn.HandshakeState.State13.KeyShareKeys
	if ksk == nil || ksk.Ecdhe == nil {
		uConn.Close()
		return nil, fmt.Errorf("uTLS did not allocate X25519 KeyShareKeys (need standalone X25519 in client_shares)")
	}
	ephPub := ksk.Ecdhe.PublicKey().Bytes()
	if len(ephPub) != x25519KeyLen {
		uConn.Close()
		return nil, fmt.Errorf("uTLS Ecdhe pubkey length %d, want %d", len(ephPub), x25519KeyLen)
	}
	shortID := c.pickShortID()

	// Compute samizdat ECDH using uTLS's Ecdhe priv against the server's static pub.
	serverStaticPub, err := ecdh.X25519().NewPublicKey(c.config.PublicKey)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("parsing server static pub: %w", err)
	}
	shared, err := ksk.Ecdhe.ECDH(serverStaticPub)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("ECDH(uTLS Ecdhe priv, server static pub): %w", err)
	}
	psk, err := DerivePSKFromSharedSecret(shared, shortID)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("deriving samizdat PSK from shared secret: %w", err)
	}
	sessionID, err := BuildSessionIDv1(psk, shortID, ephPub, nil)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("building session ID v1: %w", err)
	}

	// Inject SessionID into the (already-built) handshake state and re-marshal.
	// No 0xFE0C extension is added -- server reads the pubkey from the standard
	// key_share extension instead.
	uConn.HandshakeState.Hello.SessionId = make([]byte, len(sessionID))
	copy(uConn.HandshakeState.Hello.SessionId, sessionID[:])
	if err := uConn.MarshalClientHello(); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("re-marshaling ClientHello after SessionID inject: %w", err)
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		if fragmenter != nil {
			fragmenter.ReportOutcome(false)
		}
		uConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	state := uConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		if fragmenter != nil {
			fragmenter.ReportOutcome(false)
		}
		uConn.Close()
		return nil, fmt.Errorf("expected h2, got %q", state.NegotiatedProtocol)
	}
	if fragmenter != nil {
		fragmenter.ReportOutcome(true)
	}

	transport, err := newH2Transport(uConn, c.config.ServerAddr, c.config.MaxStreamsPerConn, c.shaper, c.fragmenter, c.config.DrainTimeout, class, sni)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("creating H2 transport: %w", err)
	}
	if c.bundleCtx != nil {
		go func() {
			_ = c.fetchAndApplyBundle(c.bundleCtx, transport)
		}()
	}

	return transport, nil
}

func (c *Client) fetchAndApplyBundle(parent context.Context, transport *h2Transport) (err error) {
	if parent == nil || transport == nil || transport.h2Roundtrip == nil {
		return nil
	}
	defer func() {
		if err != nil {
			safeIntAdd(bundleFetchErrorsTotal, 1)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+transport.serverAddr, nil)
	if err != nil {
		return err
	}
	req.Host = configAuthority
	req.Header.Set(SamizdatProtocolHeader, SamizdatProtocolConfig)
	resp, err := transport.h2Roundtrip.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config bundle status %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, MaxCoverConfigBundleBytes+1))
	if err != nil {
		return err
	}
	if len(buf) == 0 {
		return nil
	}
	if len(buf) > MaxCoverConfigBundleBytes {
		return fmt.Errorf("config bundle too large: %d > %d", len(buf), MaxCoverConfigBundleBytes)
	}
	var bundle CoverConfigBundle
	if err := json.Unmarshal(buf, &bundle); err != nil {
		return err
	}
	if err := bundle.Validate(nil, false); err != nil {
		return err
	}
	safeIntAdd(bundleReceivedTotal, 1)
	c.applyCoverConfigBundle(&bundle)
	safeIntAdd(bundleAppliedTotal, 1)
	return nil
}

func (c *Client) applyCoverConfigBundle(bundle *CoverConfigBundle) {
	if bundle == nil {
		return
	}
	if bundle.EpochKey != "" && bundle.ShortIDPoolSize > 0 {
		derived := DeriveShortIDPool(c.config.MasterShortID, bundle.EpochKey, bundle.ShortIDPoolSize)
		poolCopy := append([][8]byte(nil), derived...)
		c.derivedShortIDs.Store(&poolCopy)
	} else {
		empty := [][8]byte{}
		c.derivedShortIDs.Store(&empty)
	}
	if len(bundle.SNIPool) > 0 {
		sniCopy := append([]SNIEntry(nil), bundle.SNIPool...)
		c.serverPushedSNIPool.Store(&sniCopy)
	} else {
		empty := []SNIEntry{}
		c.serverPushedSNIPool.Store(&empty)
	}
	if c.cover != nil {
		if len(bundle.CoverTargets) > 0 {
			c.cover.replaceTargets(bundle.CoverTargets)
		}
		if bundle.CoverGapMinMS > 0 || bundle.CoverGapMaxMS > 0 {
			c.cover.replaceGap(time.Duration(bundle.CoverGapMinMS)*time.Millisecond, time.Duration(bundle.CoverGapMaxMS)*time.Millisecond)
		}
	}
	// VK TURN credentials: store for future TURN transport implementation.
	// Currently a forward-compatible placeholder; the client-side TURN
	// dialer will read these when implemented.
	if bundle.TURNCreds != nil {
		entry := *bundle.TURNCreds
		c.serverPushedTURNCreds.Store(&entry)
	}
	// Phase C iOS-notify: forward a one-shot user-facing notification to any
	// registered consumer (iOS NE bridges this to a local notification).
	// Fire on a goroutine to keep the bundle-apply path non-blocking; the
	// callback may do I/O (UserDefaults write, sendProviderMessage) we don't
	// want to serialize against transport rotation. Copy the entry by value
	// before launching — the caller may reuse the bundle.
	if bundle.Notification != nil && c.config.OnNotification != nil {
		entry := *bundle.Notification
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// Don't propagate consumer panics into the client pool.
					_ = r
				}
			}()
			c.config.OnNotification(entry)
		}()
	}
}

type tlsConnWrapper struct {
	*utls.UConn
}

func (w *tlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := w.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:            state.Version,
		HandshakeComplete:  state.HandshakeComplete,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
	}
}

// TopRealtimeFlowSnapshot is a debug accessor — returns the busiest UDP flow
// the detector currently tracks (highest pkts). Used for rate-stickylock
// tuning observation via expvar.
func (c *Client) TopRealtimeFlowSnapshot() TopRealtimeFlowStats {
	if c == nil || c.realtime == nil || c.realtime.Detector == nil {
		return TopRealtimeFlowStats{}
	}
	return c.realtime.Detector.TopRealtimeFlowSnapshot()
}

// ServerPushedTURNCreds returns the most recently received VK TURN
// credentials from the server's CoverConfigBundle. Returns nil if the
// server has not pushed any credentials yet (e.g. turncreds manager
// disabled or credentials not yet fetched).
func (c *Client) ServerPushedTURNCreds() *TURNCredsEntry {
	if c == nil {
		return nil
	}
	return c.serverPushedTURNCreds.Load()
}

// RTTProbeSnapshot returns the current RTT probe stats — last p50 in ms for
// each shape (lite vs bulk), sample counts, and the most-recent measurement.
// Returns -1 fields if probe has not collected samples yet.
func (c *Client) RTTProbeSnapshot() RTTProbeStats {
	if c == nil || c.rttProbe == nil {
		return RTTProbeStats{LiteP50Ms: -1, BulkP50Ms: -1, LastMs: -1}
	}
	return c.rttProbe.Snapshot()
}

// LockedFlowsSnapshot — debug accessor to see currently-locked flows for tuning.
func (c *Client) LockedFlowsSnapshot() []LockedFlowSnapshot {
	if c == nil || c.realtime == nil || c.realtime.Detector == nil {
		return nil
	}
	return c.realtime.Detector.LockedFlowsSnapshot()
}
