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

// boolPtr returns a pointer to the given bool; used so callers can express
// "leave at secure default" (nil) vs "explicitly on/off".
func boolPtr(b bool) *bool { return &b }

// ClientConfig configures the Samizdat client.
type ClientConfig struct {
	// Server connection
	ServerAddr string // host:port of the Samizdat server
	ServerName string // cover site SNI (e.g. "ok.ru")

	// Authentication
	PublicKey []byte  // server X25519 public key (32 bytes)
	ShortID   [8]byte // pre-shared 8-byte identifier

	// TLS fingerprint
	Fingerprint string // "chrome" (default), "firefox", "safari"

	// Traffic shaping
	// EnableBBCR controls the P0.5 BBCR transport. Nil means secure default (true).
	// Setting it to false is an emergency/test-only rollback to the legacy
	// per-destination CONNECT path and is not a permanent security mode.
	EnableBBCR *bool

	// TCP fragmentation (Geneva-inspired)
	TCPFragmentation    bool // fragment ClientHello across TCP segments (default: true)
	RecordFragmentation bool // fragment inner TLS records across H2 DATA frames (default: true)

	// DisableDefaultSecurity, when true, suppresses the automatic-true defaults
	// for TCPFragmentation / RecordFragmentation. Tests flip this on when they
	// need deterministic no-shaping behaviour; EnableBBCR still defaults true.
	DisableDefaultSecurity bool

	// Connection management
	MaxStreamsPerConn     int           // legacy max H2 streams per TCP conn (default: 100)
	IdleTimeout           time.Duration // close idle connections after (default: 5m)
	ConnectTimeout        time.Duration // TCP+TLS connect timeout (default: 15s)
	BytesPerFlowThreshold int           // mark legacy outer draining before long-flow shaping (default: 12288)
	BytesThresholdJitter  float64       // per-flow threshold randomization, ±fraction (default: 0.30)
	DrainTimeout          time.Duration // close draining connections after (default: 10s)
	BBCRChurnRate         float64       // new outer dial token rate per (server,sni), default 0.5/sec
	BBCRChurnBurst        int           // new outer dial burst, default 6
	BBCRAlwaysCautious    bool          // force BBCR cautious rotation mode regardless of detector

	// NoiseFrames is reserved for future client-originated BBCR NOISE. Server-side
	// BBCR NOISE is controlled by ServerConfig.NoiseEnabled.
	NoiseFrames bool

	// Optional: custom dialer for the underlying TCP connection
	Dialer DialFunc
}

// applyDefaults fills in zero-value fields with sensible defaults.
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
	if c.BytesPerFlowThreshold == 0 {
		c.BytesPerFlowThreshold = 12 * 1024
	}
	if c.BytesThresholdJitter == 0 {
		c.BytesThresholdJitter = 0.30
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}
	if c.BBCRChurnRate == 0 {
		c.BBCRChurnRate = 0.5
	}
	if c.BBCRChurnBurst == 0 {
		c.BBCRChurnBurst = 6
	}
	if c.EnableBBCR == nil {
		c.EnableBBCR = boolPtr(true)
	}
	if !c.DisableDefaultSecurity {
		// Security defaults: all countermeasures on unless explicitly disabled.
		// (Fields default to false because Go, so we flip them here.)
		c.TCPFragmentation = c.TCPFragmentation || true
		c.RecordFragmentation = c.RecordFragmentation || true
		c.NoiseFrames = c.NoiseFrames || true
	}
}

// ServerConfig configures the Samizdat server.
type ServerConfig struct {
	// Listen address
	ListenAddr string // e.g. ":8443"

	// Authentication
	PrivateKey []byte    // server X25519 private key (32 bytes)
	ShortIDs   [][8]byte // allowed client short IDs

	// TLS certificate (for the real server identity)
	CertPEM []byte
	KeyPEM  []byte

	// Masquerade: TCP-level transparent proxy to real domain when auth fails
	MasqueradeDomain      string        // domain to masquerade as (e.g. "ok.ru")
	MasqueradeAddr        string        // optional IP:port override (default: resolve domain)
	MasqueradeIdleTimeout time.Duration // close after no data (default: 5m)
	MasqueradeMaxDuration time.Duration // absolute max proxy duration (default: 10m)

	// Traffic shaping (server side — applies to response writes)
	// EnableBBCR defaults true. False is emergency/test-only rollback to the
	// legacy per-destination CONNECT handler; P0.5 acceptance requires true.
	EnableBBCR            *bool
	RecordFragmentation   bool          // default: true — split outer TLS records
	NoiseFrames           bool          // deprecated alias; default true when DisableDefaultSecurity=false
	NoiseEnabled          *bool         // nil/default true — send BBCR NOISE frames; false disables P1.2
	BytesPerFlowThreshold int           // mark legacy outer draining before long-flow shaping (default: 12288)
	BytesThresholdJitter  float64       // per-flow threshold randomization, ±fraction (default: 0.30)
	DrainTimeout          time.Duration // close draining connections after (default: 10s)
	BBCRAlwaysCautious    bool          // force BBCR cautious rotation mode regardless of detector

	// ReplayWindow defines the server-side seen-nonce cache duration.
	// Samizdat SessionIDs are bound to a coarse timestamp; a ClientHello
	// older than ReplayWindow (or already-seen) is routed to masquerade.
	// Default: 2 minutes.
	ReplayWindow time.Duration

	// Debug gates verbose log.Printf output and the localhost expvar endpoint.
	// Default off — production builds must not leak CONNECT destinations,
	// handler state transitions, recovered-panic traces, or /debug/vars into
	// observable logs/listeners; those are forensic goldmines and can be
	// cross-correlated with wire traffic to identify authenticated flows
	// (cf. audit T5 log-distinguisher finding).
	Debug bool
	// DebugListenAddr controls the Debug=true expvar HTTP listener. Empty means
	// 127.0.0.1:6060. Ignored when Debug=false.
	DebugListenAddr string

	// DisableDefaultSecurity turns off the auto-true defaults (tests only).
	DisableDefaultSecurity bool

	// Limits
	MaxConcurrentStreams       int           // per connection (default: 250)
	BBCRMaxSessionsPerIdentity int           // default 16
	BBCRMaxStreamsPerSession   int           // default 100
	BBCRSessionIdleTimeout     time.Duration // default 60s

	// Handler: called for each authenticated proxied connection
	Handler ConnHandler
}

// applyDefaults fills in zero-value fields with sensible defaults.
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
	if c.BBCRMaxSessionsPerIdentity == 0 {
		c.BBCRMaxSessionsPerIdentity = 16
	}
	if c.BBCRMaxStreamsPerSession == 0 {
		c.BBCRMaxStreamsPerSession = 100
	}
	if c.BBCRSessionIdleTimeout == 0 {
		c.BBCRSessionIdleTimeout = 60 * time.Second
	}
	if c.ReplayWindow == 0 {
		c.ReplayWindow = 2 * time.Minute
	}
	if c.BytesPerFlowThreshold == 0 {
		c.BytesPerFlowThreshold = 12 * 1024
	}
	if c.BytesThresholdJitter == 0 {
		c.BytesThresholdJitter = 0.30
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}
	if c.EnableBBCR == nil {
		c.EnableBBCR = boolPtr(true)
	}
	if c.NoiseEnabled == nil {
		c.NoiseEnabled = boolPtr(true)
	}
	if !c.DisableDefaultSecurity {
		c.RecordFragmentation = c.RecordFragmentation || true
		c.NoiseFrames = c.NoiseFrames || true
	}
}
