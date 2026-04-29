// Package samizdat implements a censorship circumvention protocol that makes
// proxy traffic indistinguishable from a browser visiting a real website over
// HTTP/2. It uses a single TLS layer with Reality-style authentication,
// HTTP/2 CONNECT tunneling, multiplexed streams, Geneva-inspired TCP
// fragmentation, and traffic shaping with record fragmentation and delayed ACK defense.
//
// The server acts as a real web server to unauthorized connections by
// transparently proxying them to the masquerade domain at the TCP level.
package samizdat

import (
	"context"
	"net"
	"time"
)

// DialFunc allows injecting a custom TCP dialer for the underlying connection.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ConnHandler is called for each proxied connection with destination info.
type ConnHandler func(ctx context.Context, conn net.Conn, destination string)

// ClientConfig configures the Samizdat client.
type ClientConfig struct {
	// Server connection
	ServerAddr string
	ServerName string

	// Authentication
	PublicKey []byte
	ShortID   [8]byte

	// TLS fingerprint
	Fingerprint string

	// TCP fragmentation (Geneva-inspired)
	TCPFragmentation    bool
	RecordFragmentation bool

	// DisableDefaultSecurity, when true, suppresses the automatic-true defaults
	// for TCPFragmentation / RecordFragmentation. Tests flip this on when they
	// need deterministic no-shaping behaviour.
	DisableDefaultSecurity bool

	// Connection management
	MaxStreamsPerConn int
	IdleTimeout       time.Duration
	ConnectTimeout    time.Duration
	DrainTimeout      time.Duration

	// Optional: custom dialer for the underlying TCP connection
	Dialer DialFunc
}

func (c *ClientConfig) applyDefaults() {
	if c.Fingerprint == "" {
		c.Fingerprint = "chrome"
	}
	if c.MaxStreamsPerConn == 0 {
		c.MaxStreamsPerConn = 100
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 15 * time.Second
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}
	if !c.DisableDefaultSecurity {
		// iOS-vendor patch: original was `c.TCPFragmentation = c.TCPFragmentation || true`
		// which is always true, silently overriding any caller-supplied
		// `false`. Force-on is the intended behaviour, so just write it
		// directly. (The boolean tautology was upstream code rot.)
		c.TCPFragmentation = true
		c.RecordFragmentation = true
	}
}

// ServerConfig configures the Samizdat server.
type ServerConfig struct {
	ListenAddr string

	PrivateKey []byte
	ShortIDs   [][8]byte

	CertPEM []byte
	KeyPEM  []byte

	MasqueradeDomain      string
	MasqueradeAddr        string
	MasqueradeIdleTimeout time.Duration
	MasqueradeMaxDuration time.Duration

	RecordFragmentation bool
	DrainTimeout        time.Duration

	// ReplayWindow defines the server-side seen-nonce cache duration.
	ReplayWindow time.Duration

	// Debug gates verbose log.Printf output and the localhost expvar endpoint.
	Debug           bool
	DebugListenAddr string

	DisableDefaultSecurity bool

	MaxConcurrentStreams int

	Handler ConnHandler
}

func (c *ServerConfig) applyDefaults() {
	if c.MasqueradeIdleTimeout == 0 {
		c.MasqueradeIdleTimeout = 5 * time.Minute
	}
	if c.MasqueradeMaxDuration == 0 {
		c.MasqueradeMaxDuration = 10 * time.Minute
	}
	if c.MaxConcurrentStreams == 0 {
		c.MaxConcurrentStreams = 250
	}
	if c.ReplayWindow == 0 {
		c.ReplayWindow = 2 * time.Minute
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}
	if !c.DisableDefaultSecurity {
		c.RecordFragmentation = c.RecordFragmentation || true
	}
}
