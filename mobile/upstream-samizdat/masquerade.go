package samizdat

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Masquerade implements a TCP-level transparent proxy to the real masquerade
// domain. When the server receives a connection that fails Samizdat auth
// verification, it enters masquerade mode: the buffered raw ClientHello is
// forwarded to the real domain, and bidirectional TCP proxying begins.
//
// This makes the server indistinguishable from the real domain to active
// probes — the probe completes a real TLS handshake with the real domain's
// certificate and receives real HTTP responses.
type Masquerade struct {
	OriginAddr   string        // IP:port of real domain (or resolved from domain)
	OriginDomain string        // domain name for DNS resolution
	IdleTimeout  time.Duration // close after no data (default: 5m)
	MaxDuration  time.Duration // absolute max proxy duration (default: 10m)
	DialTimeout  time.Duration // timeout connecting to origin (default: 10s)
}

// NewMasquerade creates a new masquerade proxy with defaults.
func NewMasquerade(domain, addr string, idleTimeout, maxDuration time.Duration) *Masquerade {
	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}
	if maxDuration == 0 {
		maxDuration = 10 * time.Minute
	}
	return &Masquerade{
		OriginAddr:   addr,
		OriginDomain: domain,
		IdleTimeout:  idleTimeout,
		MaxDuration:  maxDuration,
		DialTimeout:  10 * time.Second,
	}
}

type idleConn struct {
	net.Conn
	idle        time.Duration
	maxDeadline time.Time
}

func (c *idleConn) Read(p []byte) (int, error) {
	deadline := c.readDeadline()
	if !deadline.IsZero() {
		_ = c.Conn.SetReadDeadline(deadline)
	}
	return c.Conn.Read(p)
}

func (c *idleConn) readDeadline() time.Time {
	if c.idle <= 0 {
		return c.maxDeadline
	}
	deadline := time.Now().Add(c.idle)
	if !c.maxDeadline.IsZero() && c.maxDeadline.Before(deadline) {
		return c.maxDeadline
	}
	return deadline
}

// ProxyConnection forwards a non-authenticated connection to the real domain.
// clientHello contains the buffered raw ClientHello bytes that triggered the
// auth check failure. conn is the raw TCP connection from the probe (pre-TLS).
// ProxyConnectionWithOrigin is the SNI-aware variant. originDomain overrides
// m.OriginDomain when non-empty (cover-SNI rotation -- compass P1.1). If
// originDomain is empty, falls back to default m.OriginDomain. originAddr
// is recomputed from originDomain unless explicitly overridden.
func (m *Masquerade) ProxyConnectionWithOrigin(conn net.Conn, clientHello []byte, originDomain string) error {
	var addr string
	switch {
	case originDomain == "" || originDomain == m.OriginDomain:
		// Default origin — honour MasqueradeAddr override if set.
		addr = m.OriginAddr
		if addr == "" {
			addr = net.JoinHostPort(m.OriginDomain, "443")
		}
	default:
		// Pool entry — resolve via DNS to its own :443.
		addr = net.JoinHostPort(originDomain, "443")
	}
	return m.proxyTo(conn, clientHello, addr)
}

func (m *Masquerade) ProxyConnection(conn net.Conn, clientHello []byte) error {
	addr := m.OriginAddr
	if addr == "" {
		addr = net.JoinHostPort(m.OriginDomain, "443")
	}
	return m.proxyTo(conn, clientHello, addr)
}

// proxyTo carries the actual TCP-level forward to a resolved address.
// Shared between ProxyConnection (default) and ProxyConnectionWithOrigin
// (SNI-routed pool).
func (m *Masquerade) proxyTo(conn net.Conn, clientHello []byte, addr string) error {
	// Connect to the real domain
	originConn, err := net.DialTimeout("tcp", addr, m.DialTimeout)
	if err != nil {
		return fmt.Errorf("connecting to masquerade origin %s: %w", addr, err)
	}

	// Forward the buffered ClientHello that we already read
	if len(clientHello) > 0 {
		if _, err := originConn.Write(clientHello); err != nil {
			originConn.Close()
			return fmt.Errorf("forwarding ClientHello to origin: %w", err)
		}
	}

	// Set absolute max duration deadline, then wrap both read sides with a
	// shorter rolling idle deadline. The wrapper never extends reads past the
	// absolute max deadline.
	deadline := time.Now().Add(m.MaxDuration)
	conn.SetDeadline(deadline)
	originConn.SetDeadline(deadline)
	clientConn := &idleConn{Conn: conn, idle: m.IdleTimeout, maxDeadline: deadline}
	originIdleConn := &idleConn{Conn: originConn, idle: m.IdleTimeout, maxDeadline: deadline}

	// Bidirectional proxy: two goroutines running io.Copy
	var wg sync.WaitGroup
	var copyErr error
	var errOnce sync.Once

	wg.Add(2)

	// probe -> origin
	go func() {
		defer wg.Done()
		n, err := io.Copy(originIdleConn, clientConn)
		masqueradeBytesForwarded.Add(n)
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Signal the other direction to stop
		if tc, ok := originConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// origin -> probe
	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, originIdleConn)
		masqueradeBytesForwarded.Add(n)
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Signal the other direction to stop
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()

	originConn.Close()
	conn.Close()

	return copyErr
}
