// Package socksstub is the gomobile-bound entry point for the main-app-side
// SOCKS5 listener that the Path 3 architecture uses. The hev-socks5-tunnel
// instance running inside the iOS extension forwards every TCP/UDP flow to
// this listener; the extension never speaks the proxy protocol itself, so
// it stays well under iOS's NEPacketTunnelProvider memory cap.
//
// Two operating modes:
//
//   - Stub mode: direct dial. The listener accepts SOCKS5 CONNECT requests
//     and dials the upstream destination directly. Useful for POC testing
//     of the architecture (proves the IPC + lifecycle work end-to-end)
//     without depending on samizdat.
//
//   - Samizdat mode: forward via Client.DialContext / Client.DialUDP.
//     This is the production path. Activated by SetSamizdatConfig with
//     a samizdat:// URL.
//
// Public gomobile API:
//
//   func Start(socketPath string) error
//   func Stop()
//   func Status() string                       // "stopped" | "listening"
//   func ConnectionsCount() int
//   func SetSamizdatConfig(blob string) error  // empty string → direct dial
//   func Logs() string
package socksstub

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Project renamed samizdat -> tamizdat (2026-05-01). Local alias
	// kept as `samizdat` to minimise the diff; the imported package
	// is github.com/detectqq/tamizdat (`package tamizdat`). All call
	// sites continue to use `samizdat.Client` etc. via this alias.
	samizdat "github.com/detectqq/tamizdat"
)

const (
	socksVersion5      = 0x05
	socksMethodNoAuth  = 0x00
	socksCmdConnect    = 0x01
	socksCmdUDPAssoc   = 0x03
	// socksCmdFwdUDP is hev-socks5-tunnel's custom command for
	// "UDP-in-TCP" forwarding (HEV_SOCKS5_REQ_CMD_FWD_UDP). It is what
	// hev sends when the YAML has `socks5.udp: 'tcp'`. After the SOCKS5
	// reply, the same TCP connection carries length-prefixed UDP
	// datagrams, each with its own destination address (multi-target).
	// Wire format per packet:
	//   datlen (2 BE) | hdrlen (1) | atype (1) | addr (4/16/var) | port (2 BE) | data
	// where hdrlen == 3 + addrlen-incl-atype-and-port.
	socksCmdFwdUDP     = 0x05
	socksAtypIPv4      = 0x01
	socksAtypDomain    = 0x03
	socksAtypIPv6      = 0x04
	socksReplySuccess  = 0x00
	socksReplyHostUnk  = 0x04
	socksReplyConnRef  = 0x05
	socksReplyCmdNoSup = 0x07
	socksReplyAtypNo   = 0x08
)

type runtimeState struct {
	mu             sync.Mutex
	listener       net.Listener
	cancel         context.CancelFunc
	ctx            context.Context
	socketPath     string
	logs           []string
	logsMax        int
	samizdatBlob   string           // empty → direct dial mode
	samizdatClient *samizdat.Client // nil unless SetSamizdatConfig succeeded
	connsActive    atomic.Int64
	connsTotal     atomic.Uint64
	// IPA-X: poolVariant ("", "v1", "v2", "v3") drives ClientConfig.PoolVariant
	// on the next samizdat.NewClient call. Empty == "v1" (preserves
	// IPA-G default). Toggled by Swift via SocksstubSetPoolVariant
	// before re-calling SocksstubSetSamizdatConfig with the same blob.
	// When variant is "v1" we also flip StrictSingleH2=true to match
	// Windows-GUI behaviour ("V1 radio engages strict-single-h2").
	poolVariant atomic.Value // string
}

var rt = &runtimeState{logsMax: 500}

// Log file mirror — same App Group file the extension writes to. The
// main-app side calls SetLogSink at startup so SocksStub heartbeats
// appear in the same unified log the user sees in the LogView.
var (
	logSinkMu sync.Mutex
	logSink   *os.File
)

// IPA-Z6: per-flow noise gate. When false, the high-volume "accept #N",
// "conn#N dial", "conn#N closed", "udp#N session open/end/new target"
// lines are suppressed. Errors, warnings, config events, and the
// heartbeat from Swift still appear. Default false — operator's
// crash-diagnosis log was getting drowned in per-packet trivia.
var verboseFlowLogs atomic.Bool

// SetVerboseFlowLogs toggles per-flow log emission. Exposed to Swift as
// SocksstubSetVerboseFlowLogs(bool) for a future debug toggle.
func SetVerboseFlowLogs(enabled bool) {
	verboseFlowLogs.Store(enabled)
	if enabled {
		rt.appendLog("info: verbose per-flow logs = ON")
	} else {
		rt.appendLog("info: verbose per-flow logs = OFF (errors+heartbeat only)")
	}
}

// flowLogf is a gated wrapper for per-flow info logs. Errors and
// warnings should still use rt.appendLog directly so they're never
// suppressed.
func flowLogf(format string, args ...interface{}) {
	if !verboseFlowLogs.Load() {
		return
	}
	rt.appendLog(fmt.Sprintf(format, args...))
}

// SetLogSink opens the given path in append mode (creating if necessary).
// Pass an empty string to detach.
func SetLogSink(path string) {
	if path == "" {
		logSinkMu.Lock()
		if logSink != nil {
			logSink.Close()
			logSink = nil
		}
		logSinkMu.Unlock()
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	logSinkMu.Lock()
	if logSink != nil {
		logSink.Close()
	}
	logSink = f
	logSinkMu.Unlock()
}

// Start opens a SOCKS5 listener.
//
//   - addrSpec starting with "/" or "unix:" → UNIX domain socket. Used
//     when the consumer also lives in the same App Group container.
//   - otherwise treated as a TCP "host:port". hev-socks5-tunnel doesn't
//     parse UNIX sockets in its config, so the actual Path 3 ext-to-app
//     bridge uses TCP on 127.0.0.1 with a fixed port.
//
// Idempotent — calling again with a different addr is a no-op (Stop
// first). Returns immediately; the accept loop runs in the background.
func Start(addrSpec string) error {
	rt.mu.Lock()
	if rt.listener != nil {
		rt.mu.Unlock()
		return errors.New("already listening")
	}
	rt.mu.Unlock()

	// Pin the Go runtime under iOS's NEPacketTunnelProvider memory cap.
	// iOS jetsam-reaps the extension if RSS approaches ~50 MB.
	//
	// IPA-Z5: bump soft limit 25 MB → 37 MB (sing-box-for-apple's
	// formula: 75% of the 50 MB jetsam cap). At 25 MB the GC pacer was
	// running so aggressively that small bursts couldn't be absorbed
	// without paging — and the headroom we kept (25 MB unused) was
	// just sitting useless because Go won't touch it. 37 MB lets the
	// heap actually breathe under speedtest fanout while still leaving
	// 13 MB headroom for non-Go state (Swift, hev, NEPacketTunnel
	// internals). GOGC=20 (steeper-than-default GC ramp) is kept —
	// Go's pacer will start aggressive collection well before 37 MB.
	debug.SetMemoryLimit(37 * 1024 * 1024)
	debug.SetGCPercent(20)

	network := "tcp"
	addr := addrSpec
	if len(addrSpec) > 0 && (addrSpec[0] == '/' || (len(addrSpec) > 5 && addrSpec[:5] == "unix:")) {
		network = "unix"
		if addrSpec[0] != '/' {
			addr = addrSpec[5:]
		}
		_ = os.Remove(addr)
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", network, addr, err)
	}
	if network == "unix" {
		_ = os.Chmod(addr, 0o600)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt.mu.Lock()
	rt.listener = ln
	rt.ctx = ctx
	rt.cancel = cancel
	rt.socketPath = addr
	rt.mu.Unlock()

	rt.appendLog(fmt.Sprintf("info: socks listener up on %s://%s", network, addr))
	go acceptLoop(ctx, ln)
	return nil
}

// Stop closes the listener and any active connections.
func Stop() {
	rt.mu.Lock()
	ln := rt.listener
	cancel := rt.cancel
	path := rt.socketPath
	rt.listener = nil
	rt.cancel = nil
	rt.ctx = nil
	rt.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	// Remove only if it looks like a UDS path (TCP "127.0.0.1:1080"
	// would not be a valid path).
	if path != "" && len(path) > 0 && path[0] == '/' {
		_ = os.Remove(path)
	}
	rt.appendLog("info: socks listener stopped")
}

// Status returns "stopped" or "listening".
func Status() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.listener == nil {
		return "stopped"
	}
	return "listening"
}

// ConnectionsActive returns the number of currently-open client conns.
func ConnectionsActive() int {
	return int(rt.connsActive.Load())
}

// ConnectionsTotal returns the running total of connections accepted
// since the listener started (does not reset on stop).
func ConnectionsTotal() int64 {
	return int64(rt.connsTotal.Load())
}

// SetSamizdatConfig switches the listener between direct-dial mode (empty
// string) and samizdat mode (samizdat:// URL). The next accepted SOCKS5
// connection will use the new mode.
//
// On a samizdat:// URL we instantiate a *samizdat.Client up-front so the
// (potentially expensive) uTLS+H2 handshake to the upstream proxy server
// happens once, lazily, on the first dial — instead of every dial.
func SetSamizdatConfig(blob string) error {
	if blob == "" {
		rt.mu.Lock()
		oldClient := rt.samizdatClient
		rt.samizdatBlob = ""
		rt.samizdatClient = nil
		rt.mu.Unlock()
		if oldClient != nil {
			_ = oldClient.Close()
		}
		rt.appendLog("info: dial mode = direct")
		return nil
	}

	cfg, err := parseSamizdatURL(blob)
	if err != nil {
		rt.appendLog(fmt.Sprintf("error: SetSamizdatConfig parse: %v", err))
		return err
	}
	pubKey, err := hex.DecodeString(cfg.PubkeyHex)
	if err != nil || len(pubKey) != 32 {
		rt.appendLog("error: SetSamizdatConfig pubkey must be 64 hex chars")
		return errors.New("pubkey: 64 hex chars required")
	}
	// Decode primary shortID (always present — parser guarantees ≥1 entry).
	primaryBytes, err := hex.DecodeString(cfg.ShortIDHex)
	if err != nil || len(primaryBytes) != 8 {
		rt.appendLog("error: SetSamizdatConfig shortid must be 16 hex chars")
		return errors.New("shortid: 16 hex chars required")
	}
	var primaryShortID [8]byte
	copy(primaryShortID[:], primaryBytes)

	// Decode optional shortID rotation pool. samizdat.Client.pickShortID
	// rotates per-fresh-transport when ShortIDs has ≥1 entry; otherwise
	// falls back to the single ShortID field.
	shortIDPool := make([][8]byte, 0, len(cfg.ShortIDsHex))
	for _, s := range cfg.ShortIDsHex {
		raw, derr := hex.DecodeString(s)
		if derr != nil || len(raw) != 8 {
			rt.appendLog(fmt.Sprintf("error: SetSamizdatConfig shortid pool entry %q invalid", s))
			return fmt.Errorf("shortid pool: %q invalid", s)
		}
		var v [8]byte
		copy(v[:], raw)
		shortIDPool = append(shortIDPool, v)
	}

	// IPA-X: read the user-selected pool variant. Default "v1" preserves
	// the IPA-G hardcoded behaviour. Variant choice maps directly to
	// tamizdat's applyDefaults() switch over PoolVariant.
	variant := currentPoolVariant()
	clientCfg := samizdat.ClientConfig{
		ServerAddr:  net.JoinHostPort(cfg.ServerHost, strconv.Itoa(cfg.ServerPort)),
		ServerName:  cfg.SNI,
		PublicKey:   pubKey,
		ShortID:     primaryShortID,
		Fingerprint: cfg.Fingerprint,
		// IPA-Z4: lift the client-side cap entirely (was 50 since IPA-F
		// audit). Real cause of the "multi-open blocks all connections"
		// symptom turned out to be H2 max-concurrent-streams, not socket
		// pressure — server now pushes 1000 via H2 SETTINGS_MAX_CONCURRENT_
		// STREAMS frame, and 0 here means "obey whatever server sent".
		// Without this, our 50 capped throughput and Roblox + Safari +
		// YouTube together would deadlock the trube as soon as ~50
		// streams piled up.
		MaxStreamsPerConn: 0,
		IdleTimeout:       30 * time.Second,
		// IPA-X: V1/V2/V3 user-selectable pool variant (was hardcoded to
		// "v1" since IPA-G). applyDefaults() pins:
		//   v1: MinTransports=1, MaxTransports=1, RotationOverlapAllowance=1
		//   v2: MinTransports=1, MaxTransports=2
		//   v3: MinTransports=2, MaxTransports=4 (Opus pool sizing)
		// In all variants the library's realtime.Detector (Plan B+ since
		// commit 1a5868b) auto-flips the bulk transport to "lite shape"
		// when it sees UDP destined for the whitelisted ports (Roblox /
		// AnyDesk / Discord voice / IANA dynamic 49152-65535) or matching
		// jitter signatures — suspending cover traffic, skipping
		// fragmentation, disabling jitter, with 30-60s hysteresis.
		PoolVariant: variant,
		// IPA-X: V1 also engages StrictSingleH2 (mirrors Windows-GUI
		// radio "V1" === --pool-variant=v1 --strict-single-h2). Strict
		// mode locks the pool to exactly 1 TCP/443 forever, no overlap,
		// no rotation — even tighter than vanilla v1.
		StrictSingleH2: variant == "v1",
		// IPA-Y: Performance mode toggle removed. Plan B+'s realtime
		// classifier auto-flips the bulk transport to ShapeLite (no
		// cover, no fragmentation, no jitter) for the duration of any
		// realtime flow + 45-90s hysteresis; the old "permanent kill
		// switch" is no longer needed. Bulk traffic keeps full DPI
		// camouflage at all times now.
	}
	rt.appendLog(fmt.Sprintf("info: client built with PoolVariant=%s StrictSingleH2=%v", variant, clientCfg.StrictSingleH2))
	// IPA-M: opt-in SNI rotation pool when the URL carried snipool=…
	// (legacy ServerNames field still present in tamizdat ClientConfig).
	if len(cfg.SNIPool) > 1 {
		clientCfg.ServerNames = cfg.SNIPool
	}
	// IPA-R rename: tamizdat removed the legacy ShortIDs []byte slice
	// field. The new model is one MasterShortID + HKDF-derived pool of
	// N entries (server pushes the size via config bundle). The client
	// derives the pool internally; URL "userinfo with comma-separated
	// shortIDs" is no longer wired through. We keep the URL parser
	// permissive and just use the first entry as MasterShortID — which
	// the library already does via ClientConfig.ShortID -> MasterShortID
	// normalisation in applyDefaults().
	_ = shortIDPool

	client, err := samizdat.NewClient(clientCfg)
	if err != nil {
		rt.appendLog(fmt.Sprintf("error: SetSamizdatConfig samizdat.NewClient: %v", err))
		return err
	}

	rt.mu.Lock()
	old := rt.samizdatClient
	rt.samizdatBlob = blob
	rt.samizdatClient = client
	rt.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	rt.appendLog(fmt.Sprintf("info: dial mode = samizdat → %s:%d (sni=%s)", cfg.ServerHost, cfg.ServerPort, cfg.SNI))

	// Warm-up dial: kick off the uTLS+H2 handshake in the background so
	// the FIRST real user flow does not eat ~1-2 s of TLS handshake on
	// top of hev's 2 s connect-timeout. Audit recommendation: target
	// the upstream proxy itself (1.1.1.1:443 won't reach upstream from
	// the test runner; we use the samizdat server's own port instead).
	go func() {
		// IPA-K: 8s was too tight for Russian cellular (Megafon TLS handshake
		// got eaten by DPI delay). 30s gives the warm-up a real chance to
		// complete on slow links; if it still fails, the log line tells us
		// whether it was TCP dial, TLS handshake, or H2 settings that died.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx, "tcp", "1.1.1.1:443")
		if err != nil {
			rt.appendLog(fmt.Sprintf("warn: samizdat warm-up dial: %v (cold start will be slower)", err))
			return
		}
		_ = conn.Close()
		rt.appendLog("info: samizdat warm-up handshake done")
	}()

	return nil
}

// samizdatConfig is the iOS-side view of a parsed samizdat:// URI.
// Per URI-SCHEME.md v2 the URI carries only the four user-facing fields
// (pbk, sni, snipool, fp); all tuning knobs (MinTransports, cover,
// fragmentation, timeouts, ...) live in samizdat.ClientConfig defaults
// via applyDefaults() and are not user-tunable from the string.
type samizdatConfig struct {
	ServerHost  string
	ServerPort  int
	SNI         string   // primary SNI (first of pool, kept for legacy code paths)
	SNIPool     []string // optional rotation pool; empty = single-SNI mode
	PubkeyHex   string
	ShortIDHex  string   // primary shortID (first of pool)
	ShortIDsHex []string // optional rotation pool (always ≥1 entry)
	Fingerprint string   // default "chrome"
}

// parseSamizdatURL parses both URL formats:
//
// xray-style (the modern format used by samizdat-server c384388+):
//
//	samizdat://<shortids>@<host>:<port>?pbk=<hex64>&sni=<host>&fp=<chrome|...>[&snipool=a,b,c]#<label>
//
// where <shortids> is one or more 16-hex shortIDs separated by commas,
// pbk is the server's X25519 static public key (also accepts pubkey=
// and public-key-hex= as aliases), and #<label> is an optional UI hint
// that the parser ignores.
//
// legacy (the older format earlier samizdat-ios builds shipped):
//
//	samizdat://<host>:<port>/?sni=<host>&pubkey=<hex64>&shortid=<hex16>&fp=<...>
//
// All keys/values are merged across both forms so downloaded URLs work
// regardless of which generator created them. Rotation pools (snipool,
// userinfo with comma-separated shortIDs) are honoured when present;
// otherwise the parsed config falls back to single-value fields.
func parseSamizdatURL(blob string) (*samizdatConfig, error) {
	u, err := url.Parse(blob)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}
	// IPA-R: project rename samizdat -> tamizdat. Accept both schemes
	// so existing URIs in the user's keychain keep working alongside
	// freshly-issued tamizdat:// links.
	if u.Scheme != "samizdat" && u.Scheme != "tamizdat" {
		return nil, fmt.Errorf("scheme must be tamizdat:// or samizdat:// (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("missing host")
	}
	portStr := u.Port()
	if portStr == "" {
		return nil, errors.New("missing port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	q := u.Query()

	// SNI: prefer snipool (xray multi-SNI for compass P1.1 rotation), fall
	// back to single sni=. A pool with one entry collapses to single-SNI.
	var sniPool []string
	if raw := q.Get("snipool"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			if t := strings.TrimSpace(s); t != "" {
				sniPool = append(sniPool, t)
			}
		}
	}
	sni := q.Get("sni")
	if sni == "" && len(sniPool) > 0 {
		sni = sniPool[0]
	}
	if sni == "" {
		return nil, errors.New("missing sni (or snipool)")
	}

	// Pubkey: pbk is the xray spelling, pubkey is legacy, public-key-hex is
	// an older alias. First non-empty wins.
	pub := q.Get("pbk")
	if pub == "" {
		pub = q.Get("pubkey")
	}
	if pub == "" {
		pub = q.Get("public-key-hex")
	}
	if len(pub) != 64 {
		return nil, errors.New("pubkey must be 64 hex chars (use pbk= or pubkey=)")
	}

	// shortIDs: userinfo (xray-style) takes priority over shortid= query
	// param when both are present. Userinfo may be a single 16-hex value
	// or comma-separated for rotation pool.
	var shortIDs []string
	if u.User != nil {
		userinfo := u.User.Username()
		for _, s := range strings.Split(userinfo, ",") {
			if t := strings.TrimSpace(s); t != "" {
				shortIDs = append(shortIDs, t)
			}
		}
	}
	if len(shortIDs) == 0 {
		if raw := q.Get("shortid"); raw != "" {
			for _, s := range strings.Split(raw, ",") {
				if t := strings.TrimSpace(s); t != "" {
					shortIDs = append(shortIDs, t)
				}
			}
		}
	}
	if len(shortIDs) == 0 {
		return nil, errors.New("missing shortid (use userinfo or shortid=)")
	}
	for _, s := range shortIDs {
		if len(s) != 16 {
			return nil, fmt.Errorf("shortid must be 16 hex chars (got %q)", s)
		}
	}

	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}

	return &samizdatConfig{
		ServerHost:  host,
		ServerPort:  port,
		SNI:         sni,
		SNIPool:     sniPool,
		PubkeyHex:   pub,
		ShortIDHex:  shortIDs[0],
		ShortIDsHex: shortIDs,
		Fingerprint: fp,
	}, nil
}

// FreeOSMemory triggers Go's runtime to return as much memory as possible
// to the OS via madvise(MADV_FREE_REUSABLE) on darwin. iOS will count
// pages we hold against our jetsam ledger even after Go has freed them
// internally; calling this from the extension's 2 s heartbeat loop
// keeps the visible process RSS as low as the live-set permits.
func FreeOSMemory() {
	debug.FreeOSMemory()
}

// SetPoolVariant selects the tamizdat connection-pool strategy on the
// next samizdat.NewClient call. Accepted values: "v1", "v2", "v3"
// (case-insensitive); anything else is normalised to "v1". Caller
// must follow up with SetSamizdatConfig to actually rebuild the
// transport. Exported for gomobile bind (becomes
// SocksstubSetPoolVariant on the Swift side).
//
// V1 additionally engages StrictSingleH2 mode (single TCP/443 forever,
// no rotation, no overlap) to mirror the Windows-GUI radio behaviour
// where "V1" === --pool-variant=v1 + --strict-single-h2.
func SetPoolVariant(variant string) {
	v := strings.ToLower(strings.TrimSpace(variant))
	switch v {
	case "v1", "v2", "v3":
		// accepted
	default:
		v = "v1"
	}
	rt.poolVariant.Store(v)
	rt.appendLog(fmt.Sprintf("info: pool variant = %s (next client build will use this)", v))
}

// currentPoolVariant returns the stored value or "v1" if unset.
func currentPoolVariant() string {
	v, _ := rt.poolVariant.Load().(string)
	if v == "" {
		return "v1"
	}
	return v
}

// Logs returns the recent in-memory log buffer joined with newlines.
func Logs() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.logs) == 0 {
		return ""
	}
	out := make([]byte, 0, 80*len(rt.logs))
	for i, l := range rt.logs {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, l...)
	}
	return string(out)
}

func (r *runtimeState) appendLog(line string) {
	stamp := time.Now().Format("15:04:05.000")
	full := stamp + " app/socks: " + line
	r.mu.Lock()
	r.logs = append(r.logs, full)
	if len(r.logs) > r.logsMax {
		drop := len(r.logs) - r.logsMax
		r.logs = append(r.logs[:0], r.logs[drop:]...)
	}
	r.mu.Unlock()

	logSinkMu.Lock()
	sink := logSink
	logSinkMu.Unlock()
	if sink != nil {
		_, _ = sink.WriteString(full + "\n")
		// IPA-G: force fsync so the Swift bridge's file poller sees
		// every line immediately. Without this, the kernel can hold
		// writes in the page cache long enough that synchronous
		// startup messages (listener-up, dial mode) get coalesced
		// behind later async writes — exactly the IPA-F mystery.
		_ = sink.Sync()
	}
}

// acceptLoop services incoming SOCKS5 client connections.
func acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rt.appendLog(fmt.Sprintf("warn: accept: %v", err))
			return
		}
		n := rt.connsTotal.Add(1)
		rt.connsActive.Add(1)
		// IPA-G: per-connection accept log. If this never appears
		// while hev says it's forwarding traffic, loopback in
		// NEPacketTunnelProvider is sandbox-blocked — the headline
		// data-plane diagnosis we need.
		flowLogf("info: accept #%d from %s", n, c.RemoteAddr())
		go func(client net.Conn, idx uint64) {
			defer client.Close()
			defer rt.connsActive.Add(-1)
			handleSocks(ctx, client, idx)
		}(c, n)
	}
}

func handleSocks(ctx context.Context, client net.Conn, idx uint64) {
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Greeting: VER NMETHODS METHODS{n}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		rt.appendLog(fmt.Sprintf("warn: conn#%d greeting read: %v", idx, err))
		return
	}
	if hdr[0] != socksVersion5 {
		rt.appendLog(fmt.Sprintf("warn: conn#%d bad version 0x%02x", idx, hdr[0]))
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		rt.appendLog(fmt.Sprintf("warn: conn#%d methods read: %v", idx, err))
		return
	}
	// Always answer "no auth".
	if _, err := client.Write([]byte{socksVersion5, socksMethodNoAuth}); err != nil {
		rt.appendLog(fmt.Sprintf("warn: conn#%d auth-resp write: %v", idx, err))
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		rt.appendLog(fmt.Sprintf("warn: conn#%d request hdr read: %v", idx, err))
		return
	}
	if req[0] != socksVersion5 {
		rt.appendLog(fmt.Sprintf("warn: conn#%d req bad version 0x%02x", idx, req[0]))
		return
	}
	host, port, err := readSocksAddr(client, req[3])
	if err != nil {
		rt.appendLog(fmt.Sprintf("warn: conn#%d addr read: %v", idx, err))
		_ = sendReply(client, socksReplyAtypNo)
		return
	}
	dest := net.JoinHostPort(host, strconv.Itoa(int(port)))

	_ = client.SetReadDeadline(time.Time{})

	switch req[1] {
	case socksCmdConnect:
		handleConnect(ctx, client, idx, dest)
	case socksCmdFwdUDP:
		// IPA-I: hev's UDP-in-TCP. The initial dest is a placeholder
		// (often 0.0.0.0:0); each datagram on the stream carries its
		// own real target address.
		handleFwdUDP(ctx, client, idx)
	default:
		rt.appendLog(fmt.Sprintf("warn: conn#%d unsupported cmd 0x%02x", idx, req[1]))
		_ = sendReply(client, socksReplyCmdNoSup)
	}
}

// readSocksAddr reads ATYP-dependent host + port from a SOCKS5 stream.
// `atyp` is the byte already consumed from the request header.
func readSocksAddr(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, fmt.Errorf("ipv4: %w", err)
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	case socksAtypDomain:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(r, ln); err != nil {
			return "", 0, fmt.Errorf("domain-len: %w", err)
		}
		buf := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, fmt.Errorf("domain: %w", err)
		}
		host = string(buf)
	case socksAtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, fmt.Errorf("ipv6: %w", err)
		}
		host = "[" + net.IP(buf).String() + "]"
	default:
		return "", 0, fmt.Errorf("bad atyp 0x%02x", atyp)
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, fmt.Errorf("port: %w", err)
	}
	return host, binary.BigEndian.Uint16(portBuf), nil
}

// handleConnect handles SOCKS5 cmd=0x01 (CONNECT) — TCP tunnel. Caller
// has already consumed the request header AND the addr/port.
func handleConnect(ctx context.Context, client net.Conn, idx uint64, dest string) {
	flowLogf("info: conn#%d dial → %s", idx, dest)
	dialStart := time.Now()
	// IPA-K: 10s was too tight for first-flow on Russian cellular where
	// TLS handshake gets delayed by DPI. 20s lets cold-cache transport
	// setup complete; warm transports return ~20ms anyway.
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	upstream, err := dialUpstream(dialCtx, dest)
	cancel()
	if err != nil {
		rt.appendLog(fmt.Sprintf("error: conn#%d dial %s failed after %dms: %v", idx, dest, time.Since(dialStart).Milliseconds(), err))
		code := byte(socksReplyHostUnk)
		var oerr *net.OpError
		if errors.As(err, &oerr) && oerr.Err != nil {
			if oerr.Err.Error() == "connection refused" {
				code = socksReplyConnRef
			}
		}
		_ = sendReply(client, code)
		return
	}
	flowLogf("info: conn#%d dial %s ok in %dms", idx, dest, time.Since(dialStart).Milliseconds())
	defer upstream.Close()

	if err := sendReply(client, socksReplySuccess); err != nil {
		rt.appendLog(fmt.Sprintf("warn: conn#%d success-reply write: %v", idx, err))
		return
	}
	relay(client, upstream)
	flowLogf("info: conn#%d closed (lifetime %dms)", idx, time.Since(dialStart).Milliseconds())
}

func sendReply(client net.Conn, code byte) error {
	// Standard 10-byte reply: bound addr 0.0.0.0:0, atyp ipv4.
	reply := []byte{socksVersion5, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := client.Write(reply)
	return err
}

// dialUpstream is the swap-point: stage 1 = direct, stage 2 = samizdat.
//
// IPA-V: if the Swift extension recorded an app-attribution hint for
// this destination via SubmitAppHint(), wrap ctx with tamizdat.
// ContextWithAppHint so the H2 CONNECT request carries a
// Tamizdat-App-Hint header. The server-side classifier (v2, deployed
// 2026-05-02) reads that header as a Tier 3 side signal and scores
// realtime apps (anydesk/roblox/discord/etc.) toward TrafficRealtime.
func dialUpstream(ctx context.Context, dest string) (net.Conn, error) {
	rt.mu.Lock()
	client := rt.samizdatClient
	rt.mu.Unlock()
	if hint := lookupAppHint("tcp", dest); hint != "" {
		ctx = samizdat.ContextWithAppHint(ctx, hint)
		rt.appendLog(fmt.Sprintf("info: app_hint=%q for tcp %s", hint, dest))
	}
	if client == nil {
		// Direct dial — POC stage 1 / fallback when no config set.
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dest)
	}
	// Stage 2: route through the samizdat H2 CONNECT tunnel.
	return client.DialContext(ctx, "tcp", dest)
}

// dialUpstreamUDP returns a net.PacketConn bound to a single target,
// either via the samizdat UDP-over-H2 tunnel or a direct UDP socket.
func dialUpstreamUDP(ctx context.Context, dest string) (net.PacketConn, error) {
	rt.mu.Lock()
	client := rt.samizdatClient
	rt.mu.Unlock()
	if hint := lookupAppHint("udp", dest); hint != "" {
		ctx = samizdat.ContextWithAppHint(ctx, hint)
		rt.appendLog(fmt.Sprintf("info: app_hint=%q for udp %s", hint, dest))
	}
	if client == nil {
		var d net.Dialer
		c, err := d.DialContext(ctx, "udp", dest)
		if err != nil {
			return nil, err
		}
		// Wrap a connected UDP socket as PacketConn-like (writes go to
		// dest; ReadFrom returns dest as Addr).
		return newConnectedUDPAdapter(c.(*net.UDPConn), dest), nil
	}
	return client.DialUDP(ctx, dest)
}

// connectedUDPAdapter wraps a "connected" *net.UDPConn so it satisfies
// net.PacketConn with the connected peer as the constant remote addr.
type connectedUDPAdapter struct {
	conn   *net.UDPConn
	target net.Addr
}

func newConnectedUDPAdapter(c *net.UDPConn, dest string) *connectedUDPAdapter {
	return &connectedUDPAdapter{conn: c, target: &udpDestAddr{s: dest}}
}

func (a *connectedUDPAdapter) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := a.conn.Read(p)
	return n, a.target, err
}

func (a *connectedUDPAdapter) WriteTo(p []byte, _ net.Addr) (int, error) {
	return a.conn.Write(p)
}
func (a *connectedUDPAdapter) Close() error                       { return a.conn.Close() }
func (a *connectedUDPAdapter) LocalAddr() net.Addr                { return a.conn.LocalAddr() }
func (a *connectedUDPAdapter) SetDeadline(t time.Time) error      { return a.conn.SetDeadline(t) }
func (a *connectedUDPAdapter) SetReadDeadline(t time.Time) error  { return a.conn.SetReadDeadline(t) }
func (a *connectedUDPAdapter) SetWriteDeadline(t time.Time) error { return a.conn.SetWriteDeadline(t) }

type udpDestAddr struct{ s string }

func (a *udpDestAddr) Network() string { return "udp" }
func (a *udpDestAddr) String() string  { return a.s }

// handleFwdUDP services hev's `socks5.udp: 'tcp'` mode (cmd=0x05). The
// initial CONNECT-style addr in the request is a placeholder; each
// datagram on the wire carries its own destination via:
//
//	datlen (2 BE) | hdrlen (1) | atype (1) | addr (4/16/var) | port (2 BE) | data
//
// where hdrlen == 3 + addrlen-incl-atype-and-port.
//
// We open ONE samizdat UDP tunnel per unique (host, port) target,
// cache it for the lifetime of this hev TCP conn, and funnel reverse-
// path datagrams from all tunnels back to the same hev TCP stream.
func handleFwdUDP(ctx context.Context, client net.Conn, idx uint64) {
	if err := sendReply(client, socksReplySuccess); err != nil {
		rt.appendLog(fmt.Sprintf("warn: udp#%d reply write: %v", idx, err))
		return
	}
	flowLogf("info: udp#%d FWD_UDP session open", idx)

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type pcKey struct {
		host string
		port uint16
	}
	type pcEntry struct {
		pc          net.PacketConn
		atyp        byte // remember the atyp for the reverse frame header
		addrEncoded []byte // pre-encoded addr+port bytes (without atyp)
	}
	var (
		pcMu     sync.Mutex
		pcs      = make(map[pcKey]*pcEntry)
		writeMu  sync.Mutex // serialize TCP writes back to hev
		datagrams atomic.Uint64
	)

	closeAll := func() {
		pcMu.Lock()
		for _, e := range pcs {
			_ = e.pc.Close()
		}
		pcs = nil
		pcMu.Unlock()
	}
	defer closeAll()

	startReverse := func(key pcKey, e *pcEntry) {
		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, _, err := e.pc.ReadFrom(buf)
				if err != nil {
					return
				}
				// Frame: datlen | hdrlen | atype | addr | port | data
				addrLen := len(e.addrEncoded) // includes port (no atyp)
				hdrLen := 3 + 1 + addrLen     // 3 = datlen+hdrlen; +1 for atyp
				frame := make([]byte, hdrLen+n)
				binary.BigEndian.PutUint16(frame[0:2], uint16(n))
				frame[2] = byte(hdrLen)
				frame[3] = e.atyp
				copy(frame[4:], e.addrEncoded)
				copy(frame[hdrLen:], buf[:n])

				writeMu.Lock()
				_, werr := client.Write(frame)
				writeMu.Unlock()
				if werr != nil {
					return
				}
			}
		}()
	}

	// Forward path: read framed datagrams from hev, look up / open
	// PacketConn for the target, write the payload.
	for {
		var hdr [3]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			flowLogf("info: udp#%d session end (%d datagrams)", idx, datagrams.Load())
			return
		}
		datLen := binary.BigEndian.Uint16(hdr[0:2])
		hdrLen := int(hdr[2])
		if hdrLen < 5 {
			rt.appendLog(fmt.Sprintf("warn: udp#%d bad hdrlen %d", idx, hdrLen))
			return
		}
		// Read atyp + addr + port (hdrLen - 3 bytes total).
		addrSection := make([]byte, hdrLen-3)
		if _, err := io.ReadFull(client, addrSection); err != nil {
			rt.appendLog(fmt.Sprintf("warn: udp#%d addr read: %v", idx, err))
			return
		}
		atyp := addrSection[0]
		host, port, err := readSocksAddr(bytes.NewReader(addrSection[1:]), atyp)
		if err != nil {
			rt.appendLog(fmt.Sprintf("warn: udp#%d parse addr: %v", idx, err))
			return
		}
		// Read data.
		data := make([]byte, datLen)
		if datLen > 0 {
			if _, err := io.ReadFull(client, data); err != nil {
				rt.appendLog(fmt.Sprintf("warn: udp#%d data read: %v", idx, err))
				return
			}
		}

		key := pcKey{host: host, port: port}
		pcMu.Lock()
		e, ok := pcs[key]
		if !ok {
			// IPA-K: 5s was too tight for slow cellular. 20s gives the
			// underlying samizdat.DialUDP enough headroom for cold-cache
			// transport setup (TCP dial + uTLS handshake + H2 settings).
			dialCtx, dialCancel := context.WithTimeout(subCtx, 20*time.Second)
			pc, derr := dialUpstreamUDP(dialCtx, net.JoinHostPort(host, strconv.Itoa(int(port))))
			dialCancel()
			if derr != nil {
				pcMu.Unlock()
				rt.appendLog(fmt.Sprintf("warn: udp#%d dial %s:%d: %v", idx, host, port, derr))
				continue
			}
			e = &pcEntry{
				pc:          pc,
				atyp:        atyp,
				addrEncoded: addrSection[1:], // addr (incl. domain-len if applicable) + port
			}
			pcs[key] = e
			startReverse(key, e)
			flowLogf("info: udp#%d new target %s:%d (active=%d)", idx, host, port, len(pcs))
		}
		pcMu.Unlock()

		if datLen > 0 {
			// Pass nil addr — samizdat's UDP PacketConn rejects any
			// address other than the tunnel's bound target. nil is
			// always accepted. For direct-dial fallback the
			// connectedUDPAdapter ignores the addr arg too.
			_, _ = e.pc.WriteTo(data, nil)
			datagrams.Add(1)
		}
	}
}

// relay copies bytes between two duplex streams until either side closes.
// Audit fix (final IPA-F): 16 KB per direction (was 32 KB). At 50 concurrent
// flows that saves ~1.6 MB of buffer RSS — small in absolute terms but
// directly comes off the extension's jetsam-shrunk available budget.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 16*1024)
		_, _ = io.CopyBuffer(b, a, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 16*1024)
		_, _ = io.CopyBuffer(a, b, buf)
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
}
