package samizdat

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/getlantern/samizdat/bbcr"
	utls "github.com/refraction-networking/utls"
)

// Client dials connections through a Samizdat server. Multiple calls to
// DialContext share the same underlying TLS+H2 connection via multiplexing.
type Client struct {
	config     ClientConfig
	pool       *connPool
	bbcr       *clientBBCR
	dialGate   bbcr.DialGate
	shaper     *Shaper
	fragmenter *RecordFragmenter
	// fingerprintChooser randomises the uTLS ClientHello per new TCP conn
	// (P1.3). Nil when rotation is disabled. BBCR pins the first pick for
	// every REBIND in the same session so uTLS fingerprints stay stable.
	fingerprintChooser *fingerprintRotator
	bbcrHelloID        utls.ClientHelloID
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
	if config.EnableBBCR != nil && *config.EnableBBCR {
		c.bbcrHelloID = c.fingerprintChooser.pick()
	}
	gate, err := bbcr.NewChurnDialGate(bbcr.ChurnConfig{Rate: config.BBCRChurnRate, Burst: config.BBCRChurnBurst})
	if err != nil {
		return nil, fmt.Errorf("creating BBCR churn gate: %w", err)
	}
	c.dialGate = gate

	c.pool = newConnPool(config.MaxStreamsPerConn, config.IdleTimeout, c.createTransport)
	if config.EnableBBCR != nil && *config.EnableBBCR {
		c.bbcr, err = newClientBBCR(c)
		if err != nil {
			return nil, err
		}
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

	if c.config.EnableBBCR != nil && *c.config.EnableBBCR {
		if c.bbcr == nil {
			return nil, fmt.Errorf("BBCR enabled but session manager is not initialized")
		}
		return c.bbcr.dial(ctx, network, address)
	}

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

// Close shuts down all connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	var err error
	if c.bbcr != nil {
		err = c.bbcr.close()
	}
	if perr := c.pool.close(); err == nil {
		err = perr
	}
	return err
}

// createTransport creates a new TLS+H2 connection to the server with
// Reality-style auth embedded in the ClientHello.
func (c *Client) createTransport(ctx context.Context) (*h2Transport, error) {
	var tcpConn net.Conn
	var err error

	if c.dialGate != nil {
		key := bbcr.DialKey{ServerIP: c.config.ServerAddr, SNI: c.config.ServerName}
		if ctxIsForcedPrewarm(ctx) {
			clientForcedPrewarmGateBypassed.Add(1)
		} else if err := c.dialGate.Wait(ctx, key); err != nil {
			return nil, fmt.Errorf("BBCR churn gate: %w", err)
		}
	}

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
	if c.config.TCPFragmentation {
		conn = NewFragmenter(tcpConn, true)
	}

	tlsConfig := &utls.Config{
		ServerName:         c.config.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	helloID := c.fingerprintChooser.pick()
	if c.config.EnableBBCR != nil && *c.config.EnableBBCR {
		helloID = c.bbcrHelloID
	}
	uConn := utls.UClient(conn, tlsConfig, helloID)

	ephPriv, ephPub, err := GenerateEphemeralKeyPair()
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	psk, err := DeriveClientPSK(ephPriv, c.config.PublicKey, c.config.ShortID)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("deriving ECDH PSK: %w", err)
	}
	sessionID, err := BuildSessionIDv1(psk, c.config.ShortID, ephPub, nil)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("building session ID v1: %w", err)
	}
	keyShareExt, err := MarshalKeyShareExtension(ephPub)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("marshaling keyshare extension: %w", err)
	}

	if err := c.applyAuthToClientHello(uConn, sessionID[:], keyShareExt); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("applying auth: %w", err)
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	state := uConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		uConn.Close()
		return nil, fmt.Errorf("expected h2, got %q", state.NegotiatedProtocol)
	}

	transport, err := newH2Transport(uConn, c.config.ServerAddr, c.config.MaxStreamsPerConn, c.shaper, c.fragmenter, c.config.BytesPerFlowThreshold, c.config.BytesThresholdJitter, c.config.DrainTimeout, c.config.EnableBBCR != nil && *c.config.EnableBBCR)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("creating H2 transport: %w", err)
	}

	return transport, nil
}

// applyAuthToClientHello modifies the uTLS ClientHello to embed the auth SessionID and P0.3 keyshare extension.
func (c *Client) applyAuthToClientHello(uConn *utls.UConn, sessionID []byte, keyShareExtension []byte) error {
	if err := uConn.BuildHandshakeState(); err != nil {
		return fmt.Errorf("building handshake state: %w", err)
	}
	uConn.HandshakeState.Hello.SessionId = make([]byte, len(sessionID))
	copy(uConn.HandshakeState.Hello.SessionId, sessionID)
	if len(keyShareExtension) > 0 {
		if len(keyShareExtension) < 4 {
			return fmt.Errorf("keyshare extension too short: %d", len(keyShareExtension))
		}
		extPayload := make([]byte, len(keyShareExtension)-4)
		copy(extPayload, keyShareExtension[4:])
		uConn.Extensions = withoutSamizdatKeyShareExtension(uConn.Extensions)
		uConn.Extensions = append(uConn.Extensions, &utls.GenericExtension{
			Id:   SamizdatKeyShareExtensionType,
			Data: extPayload,
		})
	}
	if err := uConn.MarshalClientHello(); err != nil {
		return fmt.Errorf("marshaling client hello: %w", err)
	}
	return nil
}

func withoutSamizdatKeyShareExtension(exts []utls.TLSExtension) []utls.TLSExtension {
	if len(exts) == 0 {
		return exts
	}
	filtered := exts[:0]
	for _, ext := range exts {
		if ext == nil || ext.Len() < 2 {
			filtered = append(filtered, ext)
			continue
		}
		buf := make([]byte, ext.Len())
		n, _ := ext.Read(buf)
		if n >= 2 && uint16(buf[0])<<8|uint16(buf[1]) == SamizdatKeyShareExtensionType {
			continue
		}
		filtered = append(filtered, ext)
	}
	return filtered
}

// tlsConnWrapper wraps utls.UConn to satisfy interfaces that expect
// crypto/tls.Conn methods (e.g., http2.Transport).
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
