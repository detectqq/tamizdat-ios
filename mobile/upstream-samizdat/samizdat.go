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
	ServerAddr  string
	ServerName  string   // legacy single SNI; if ServerNames empty this is used
	ServerNames []string // pool of SNIs; client picks random per fresh transport

	// Authentication. Provide either a single ShortID (legacy) or a pool via
	// ShortIDs (recommended) — client picks random per fresh transport, which
	// breaks the "all clients of one IP have identical 8-byte SessionID prefix"
	// signal flagged by compass deep-research P1.1.
	PublicKey []byte
	ShortID   [8]byte    // legacy single ID; if ShortIDs is empty this is used
	ShortIDs  [][8]byte  // pool of allowed IDs; client picks random

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

	// Cover/decoy traffic (compass v2 §5.6): periodic background CONNECTs
	// through the tunnel to cover sites. Defeats encapsulated-TLS-handshake
	// fingerprinting by mixing "browser-like" side streams with user traffic
	// on the same H2 session. Default disabled.
	CoverTrafficEnabled bool
	CoverTrafficTargets []string // empty = defaults

	// Multi-conn fallback against #490 (compass deep-research P1.2):
	// MinTransports pre-warms N parallel TLS+H2 transports up-front; new
	// streams round-robin across them so no single transport carries the
	// whole user traffic. If TSPU shapes one TCP after ~15 KB, the others
	// stay healthy and traffic continues. Default 1 = legacy behaviour
	// (single lazy transport).
	MinTransports int

	// BytesPerTransportSoftCap, if >0, marks a transport draining once its
	// cumulative outbound bytes cross the cap (typical 12-15 KB to trigger
	// just before TSPU detector #490 fires). New streams flow to other
	// transports; pool reaper spawns a replacement. 0 = disabled.
	BytesPerTransportSoftCap int64

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
	// Security defaults are ON by default (compass v2/v3): callers must opt
	// out via DisableDefaultSecurity (e.g. tests). The block below makes the
	// URI form minimal -- a samizdat:// URI does not need to carry mintr/cap/
	// cover/tcpfrag/recfrag fields; library forces the safe values.
	if !c.DisableDefaultSecurity {
		c.TCPFragmentation = true
		c.RecordFragmentation = true
		c.CoverTrafficEnabled = true
		if c.MinTransports < 2 {
			c.MinTransports = 2
		}
		if c.BytesPerTransportSoftCap == 0 {
			c.BytesPerTransportSoftCap = 13312 // ~13 KiB, before TSPU #490 ~15-20 KB shaping
		}
	} else if c.MinTransports < 1 {
		// even with security disabled, MinTransports must be >=1
		c.MinTransports = 1
	}
}

// ServerConfig configures the Samizdat server.
type ServerConfig struct {
	ListenAddr string

	PrivateKey []byte
	ShortIDs   [][8]byte

	CertPEM []byte
	KeyPEM  []byte

	MasqueradeDomain      string            // default origin if SNI not in pool
	MasqueradeAddr        string            // default origin IP override
	// MasqueradePool maps client-presented SNI -> origin host:port. Allows
	// cover-SNI rotation (compass P1.1): client picks a random SNI from a
	// pool, server forwards auth-failed probes to the matching real origin
	// so the cert/handshake behaviour matches the SNI claim. Empty string
	// value means "use MasqueradeDomain". Unknown SNI falls back to default.
	MasqueradePool        map[string]string
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
