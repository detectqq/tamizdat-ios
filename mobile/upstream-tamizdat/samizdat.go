// Package samizdat implements a censorship circumvention protocol that makes
// proxy traffic indistinguishable from a browser visiting a real website over
// HTTP/2. It uses a single TLS layer with Reality-style authentication,
// HTTP/2 CONNECT tunneling, multiplexed streams, Geneva-inspired TCP
// fragmentation, and traffic shaping with record fragmentation and delayed ACK defense.
//
// The server acts as a real web server to unauthorized connections by
// transparently proxying them to the masquerade domain at the TCP level.
package tamizdat

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
	PrimarySNI  string   // canonical URI primary SNI; normalized from ServerName
	ServerName  string   // legacy single SNI; if ServerNames empty this is used
	ServerNames []string // legacy pool of SNIs; client picks random before bundle

	// Authentication. MasterShortID is the single URI shortID used as the root
	// for HKDF-derived pools. ShortID is kept for backward-compatible
	// in-process callers and is normalized into MasterShortID by applyDefaults.
	PublicKey     []byte
	MasterShortID [8]byte
	ShortID       [8]byte // legacy single ID; normalized to MasterShortID

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

	// PoolVariant selects an operator-controlled transport-pool strategy.
	// Empty keeps the foundation/V3-shaped defaults; "v2" uses one bulk
	// transport plus one on-demand realtime lite transport.
	PoolVariant string

	// Multi-conn fallback against #490 (compass deep-research P1.2):
	// MinTransports pre-warms N parallel TLS+H2 transports up-front; new
	// streams round-robin across them so no single transport carries the
	// whole user traffic. If TSPU shapes one TCP after ~15 KB, the others
	// stay healthy and traffic continues. Default 1 = legacy behaviour
	// (single lazy transport).
	MinTransports int

	// MaxTransports caps the number of simultaneous TLS+H2 transports in the
	// pool. 0 means applyDefaults pins it to MinTransports; values below
	// MinTransports are raised to MinTransports.
	MaxTransports int

	// RotationOverlapAllowance permits this many extra transient bulk
	// transports while an old bulk transport is draining after a byte-cap
	// rotation. V1 defaults this to 1 so a single steady transport can be
	// gracefully replaced when rotation is explicitly enabled.
	RotationOverlapAllowance int

	// BytesPerTransportSoftCap, if >0, marks a transport draining once its
	// cumulative outbound bytes cross the cap (typical 12-15 KB to trigger
	// just before TSPU detector #490 fires). New streams flow to other
	// transports; pool reaper spawns a replacement. 0 = disabled.
	BytesPerTransportSoftCap int64

	// Optional: custom dialer for the underlying TCP connection
	Dialer DialFunc
}

func (c *ClientConfig) applyDefaults() {
	if c.PrimarySNI == "" {
		if c.ServerName != "" {
			c.PrimarySNI = c.ServerName
		} else if len(c.ServerNames) > 0 {
			c.PrimarySNI = c.ServerNames[0]
		}
	}
	if c.ServerName == "" {
		c.ServerName = c.PrimarySNI
	}
	var zeroShortID [8]byte
	if c.MasterShortID == zeroShortID && c.ShortID != zeroShortID {
		c.MasterShortID = c.ShortID
	}
	if c.ShortID == zeroShortID {
		c.ShortID = c.MasterShortID
	}
	if c.Fingerprint == "" {
		c.Fingerprint = "mix"
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
	// URI form minimal -- a tamizdat:// URI does not need to carry mintr/cap/
	// cover/tcpfrag/recfrag fields; library forces the safe values.
	if !c.DisableDefaultSecurity {
		c.TCPFragmentation = true
		c.RecordFragmentation = true
		c.CoverTrafficEnabled = true
		if c.PoolVariant != "v1" && c.PoolVariant != "v2" && c.MinTransports < 2 {
			c.MinTransports = 2
		}
	} else if c.MinTransports < 1 {
		// even with security disabled, MinTransports must be >=1
		c.MinTransports = 1
	}
	switch c.PoolVariant {
	case "v1":
		c.MinTransports = 1
		c.MaxTransports = 1
		if c.RotationOverlapAllowance == 0 {
			c.RotationOverlapAllowance = 1
		}
	case "v2":
		c.MinTransports = 1
		c.MaxTransports = 2
	default:
		if c.MaxTransports == 0 {
			c.MaxTransports = c.MinTransports
		}
		if c.MaxTransports < c.MinTransports {
			c.MaxTransports = c.MinTransports
		}
	}
}

// ServerConfig configures the Samizdat server.
type ServerConfig struct {
	ListenAddr string

	PrivateKey    []byte
	MasterShortID [8]byte

	CoverConfigPath         string
	CoverConfigPreviousPath string

	CertPEM []byte
	KeyPEM  []byte

	MasqueradeDomain string // default origin if SNI not in pool
	MasqueradeAddr   string // default origin IP override
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

	EpochGraceWindow int

	MaxConcurrentStreams int

	Handler ConnHandler
}

func (c *ServerConfig) applyDefaults() {
	if c.EpochGraceWindow == 0 {
		c.EpochGraceWindow = 2
	}
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
		c.ReplayWindow = defaultReplayWindow
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}
	if !c.DisableDefaultSecurity {
		c.RecordFragmentation = c.RecordFragmentation || true
	}
}
