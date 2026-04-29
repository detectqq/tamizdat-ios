package samizdat

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// Client dials connections through a Samizdat server. Multiple calls to
// DialContext share the same underlying TLS+H2 connection via multiplexing.
type Client struct {
	config             ClientConfig
	pool               *connPool
	shaper             *Shaper
	fragmenter         *RecordFragmenter
	fingerprintChooser *fingerprintRotator
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
	c.pool = newConnPool(config.MaxStreamsPerConn, config.IdleTimeout, c.createTransport)

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
	if c.config.TCPFragmentation {
		conn = NewFragmenter(tcpConn, true)
	}

	tlsConfig := &utls.Config{
		ServerName:         c.config.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	helloID := c.fingerprintChooser.pick()
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

	transport, err := newH2Transport(uConn, c.config.ServerAddr, c.config.MaxStreamsPerConn, c.shaper, c.fragmenter, c.config.DrainTimeout)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("creating H2 transport: %w", err)
	}

	return transport, nil
}

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
