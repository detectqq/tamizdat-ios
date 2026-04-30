package samizdat

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	utls "github.com/refraction-networking/utls"
)



// pickServerName returns a randomly-chosen SNI from the configured pool.
// Falls back to legacy single ServerName when no pool is configured.
// Per-transport rotation breaks the "all clients of one IP share one SNI"
// behavioural correlation flagged by compass P1.1.
func (c *Client) pickServerName() string {
	pool := c.config.ServerNames
	if len(pool) == 0 {
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
	pool := c.config.ShortIDs
	if len(pool) == 0 {
		return c.config.ShortID
	}
	if len(pool) == 1 {
		return pool[0]
	}
	var idx [8]byte
	_, _ = rand.Read(idx[:])
	i := int(binary.BigEndian.Uint64(idx[:])>>1) % len(pool) // >>1 avoids sign issues
	return pool[i]
}

// Client dials connections through a Samizdat server. Multiple calls to
// DialContext share the same underlying TLS+H2 connection via multiplexing.
type Client struct {
	config             ClientConfig
	pool               *connPool
	shaper             *Shaper
	fragmenter         *RecordFragmenter
	fingerprintChooser *fingerprintRotator
	cover              *coverDriver
	coverCtx           context.Context
	coverCancel        context.CancelFunc
	mu                 sync.Mutex
	closed             bool
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
	if config.ServerName == "" {
		return nil, fmt.Errorf("ServerName is required")
	}

	c := &Client{
		config: config,
	}

	c.shaper = NewShaper(false, 0)
	c.fragmenter = NewRecordFragmenter(config.RecordFragmentation)
	c.fingerprintChooser = newFingerprintRotator(config.Fingerprint)
	c.pool = newConnPool(config.MaxStreamsPerConn, config.IdleTimeout, config.MinTransports, config.BytesPerTransportSoftCap, c.createTransport)

	if config.CoverTrafficEnabled {
		c.coverCtx, c.coverCancel = context.WithCancel(context.Background())
		c.cover = c.startCoverTraffic(c.coverCtx, config.CoverTrafficTargets)
	}

	return c, nil
}

// DialContext opens a proxied connection to the destination through the server.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	transport, err := c.pool.getTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting transport: %w", err)
	}

	conn, err := transport.openTunnel(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("opening tunnel to %s: %w", address, err)
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

	transport, err := c.pool.getTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting transport: %w", err)
	}

	rwc, err := transport.openUDPTunnel(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("opening UDP tunnel to %s: %w", address, err)
	}

	target := &streamAddr{network: "udp", address: address}
	return newUDPFramedPacketConn(rwc, target), nil
}

// Close shuts down all connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.coverCancel != nil {
		c.coverCancel()
	}
	if c.cover != nil {
		c.cover.close()
	}
	return c.pool.close()
}

// createTransport creates a new TLS+H2 connection to the server with
// Reality-style auth embedded in the ClientHello.
func (c *Client) createTransport(ctx context.Context) (*h2Transport, error) {
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

	var conn net.Conn = tcpConn
	var fragmenter *Fragmenter
	if c.config.TCPFragmentation {
		// #7 adaptive Geneva: bandit picks strategy per server (host:port).
		// Outcome reported below after handshake completes.
		fragmenter = NewFragmenterWithStrategy(tcpConn, true, c.config.ServerAddr, "")
		conn = fragmenter
	}

	sni := c.pickServerName()
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

	transport, err := newH2Transport(uConn, c.config.ServerAddr, c.config.MaxStreamsPerConn, c.shaper, c.fragmenter, c.config.DrainTimeout)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("creating H2 transport: %w", err)
	}

	return transport, nil
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
