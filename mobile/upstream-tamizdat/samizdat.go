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
	"strings"
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

	// StrictSingleH2 enforces "one TCP/443 per user, always" mode. When true:
	//   - MinTransports = MaxTransports = 1 (no lite transport ever spawned)
	//   - BytesPerTransportSoftCap pinned to 0 (no rotation)
	//   - RotationOverlapAllowance pinned to 0
	//   - Realtime classifier still runs, but on promote it transport-wide
	//     flips the bulk H2's shapeMode to Lite for ALL streams. On last
	//     realtime close + hysteresis the bulk transport flips back to Full.
	// Trade-off: HoL blocking on shared TCP (bulk packet loss stalls voice
	// frames for ~RTO=200ms). Wins: max one entry in TSPU #546 counter
	// (src_IP, cover-SNI, JA3) per user, regardless of activity type.
	// Default false = current V1 behaviour (lite-transport spawned on demand).
	StrictSingleH2 bool

	// Optional: custom dialer for the underlying TCP connection
	Dialer DialFunc

	// OnNotification is invoked once per applied bundle when the server
	// piggy-backed a NotificationEntry. Fires on a fresh Go goroutine so
	// the bundle-apply path stays non-blocking; consumer MUST be thread-
	// safe and MUST NOT panic (panics are recovered). Phase C iOS-notify
	// pipeline — iOS NE bridges this to a local UNNotification.
	OnNotification func(NotificationEntry)
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
	// MaxStreamsPerConn = 0 (default) means "no client-side cap; rely on
	// the server's SETTINGS_MAX_CONCURRENT_STREAMS announced via h2 SETTINGS
	// frame". Set to a positive value only as a per-platform safety floor
	// (e.g. iOS PacketTunnelProvider memory-budget protection).
	if c.MaxStreamsPerConn < 0 {
		c.MaxStreamsPerConn = 0
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
		if c.PoolVariant != "v1" && c.PoolVariant != "v2" && c.PoolVariant != "v3" && c.MinTransports < 2 {
			c.MinTransports = 2
		}
	} else if c.MinTransports < 1 {
		// even with security disabled, MinTransports must be >=1
		c.MinTransports = 1
	}
	if c.StrictSingleH2 {
		c.MinTransports = 1
		c.MaxTransports = 1
		c.RotationOverlapAllowance = 0
		c.BytesPerTransportSoftCap = 0
		// Strict mode owns the pool sizing; ignore PoolVariant overrides
		// below by clearing them. Operator can still set PoolVariant for
		// telemetry/labeling, but transport count is locked to 1.
		c.PoolVariant = "v1-strict"
	}
	switch c.PoolVariant {
	case "v1", "v1-strict":
		c.MinTransports = 1
		c.MaxTransports = 1
		if c.PoolVariant == "v1-strict" {
			c.RotationOverlapAllowance = 0
			c.BytesPerTransportSoftCap = 0
		} else if c.RotationOverlapAllowance == 0 {
			c.RotationOverlapAllowance = 1
		}
	case "v2":
		c.MinTransports = 1
		c.MaxTransports = 2
	case "v3":
		// Opus pool sizing (compass review): two prewarmed transports for
		// throughput parallelism, up to four under load. Trades a slightly
		// taller TLS-conn-count fingerprint vs #546 threshold (~12) for
		// significantly better tail latency and per-flow throughput.
		c.MinTransports = 2
		c.MaxTransports = 4
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

	// ShapeEventLogPath, when non-empty, opens a SEPARATE log file (NOT
	// stderr/journalctl) and records V1 valve transitions:
	//   - valve_open  when activeRealtimeCount transitions 0 → 1 (first realtime flow)
	//   - valve_close when activeRealtimeCount transitions 1 → 0 (last realtime flow gone)
	//   - stream_open per-flow with client identity (remoteAddr+shortid) + dst+class
	// Operator-only debug aid, off by default (empty path).
	ShapeEventLogPath string

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
		c.MaxConcurrentStreams = 1000
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

// ContextWithAppHint attaches a process-name hint to ctx. Client-side
// process attribution (e.g. /proc/net/tcp lookup on Linux) uses this to
// pass the local app's name into Client.DialContext, which forwards it
// as a "Tamizdat-App-Hint" HTTP/2 CONNECT header. Server-side realtime
// classifier reads the header and applies a Tier 3 side-signal score
// boost when the app is in the operator-configured realtime-app list.
//
// Empty hint is no-op. Hint values are lower-cased + trimmed before
// transport to normalise across OSes.
func ContextWithAppHint(ctx context.Context, hint string) context.Context {
	hint = strings.ToLower(strings.TrimSpace(hint))
	if hint == "" {
		return ctx
	}
	return context.WithValue(ctx, appHintCtxKey{}, hint)
}

// AppHintFromContext returns the app hint stored on ctx via
// ContextWithAppHint, or "" if none.
func AppHintFromContext(ctx context.Context) string {
	v, _ := ctx.Value(appHintCtxKey{}).(string)
	return v
}
