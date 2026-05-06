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
//	func Start(socketPath string) error
//	func Stop()
//	func Status() string                       // "stopped" | "listening"
//	func ConnectionsCount() int
//	func SetSamizdatConfig(blob string) error  // empty string → direct dial
//	func Logs() string
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
	"runtime"
	"runtime/debug"
	"runtime/pprof"
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
	singBufio "github.com/sagernet/sing/common/bufio"
	"golang.org/x/time/rate"
)

const (
	socksVersion5     = 0x05
	socksMethodNoAuth = 0x00
	socksCmdConnect   = 0x01
	socksCmdUDPAssoc  = 0x03
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

// IPA-D6: proactive idle eviction (Shadowrocket Tier-3 pattern).
// Every active SOCKS5 flow registers itself in flowRegistry and updates
// lastActiveNano on every successful read/write iteration. A background
// goroutine ticks every 3 seconds and force-closes any flow that has
// been idle for > 5 seconds. This is NOT memory-pressure-driven —
// it runs ALL THE TIME, keeping the active set small enough that
// memory never grows large.
//
// Shadowrocket decomp showed their mem_trim handler is empty stub
// and os_proc_available_memory is used only for logging. Their actual
// stop-crank is proactive: closeIfNeeded cuts streams by count/3,
// removeAnyStreams evicts LRU idle > 10 seconds. We use 5 seconds for
// more aggressive memory containment under our heavier per-flow cost.
type flowState struct {
	conn           net.Conn
	cancel         context.CancelFunc
	createdNano    int64
	lastActiveNano atomic.Int64
}

var flowRegistry sync.Map // idx (uint64) → *flowState

const (
	idleEvictionTickInterval = 3 * time.Second
	idleEvictionThreshold    = 5 * time.Second
)

// markFlowActive bumps the lastActiveNano of a registered flow.
// Called from relay() on every successful CopyBuffer chunk.
func markFlowActive(idx uint64) {
	if v, ok := flowRegistry.Load(idx); ok {
		v.(*flowState).lastActiveNano.Store(time.Now().UnixNano())
	}
}

// startIdleEvictor launches the background ticker. Call once at Start.
func startIdleEvictor(ctx context.Context) {
	go func() {
		t := time.NewTicker(idleEvictionTickInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now().UnixNano()
				cutoff := now - idleEvictionThreshold.Nanoseconds()
				closed := 0
				flowRegistry.Range(func(k, v any) bool {
					fs := v.(*flowState)
					if fs.lastActiveNano.Load() < cutoff {
						// Idle too long. Close.
						_ = fs.conn.Close()
						if fs.cancel != nil {
							fs.cancel()
						}
						closed++
					}
					return true
				})
				if closed > 0 {
					rt.appendLog(fmt.Sprintf("info: idle-evict closed %d flows", closed))
				}
			}
		}
	}()
}

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
// heartbeat from Swift still appear.
//
// IPA-A8: back to default OFF. Each per-flow log line forces an fsync()
// on the App Group log file (see appendLog below); under YouTube/
// speedtest workload that's 10-50 fsync/sec, blocking real CPU on the
// data path while we're trying to diagnose memory pressure.
// Functional debug (is traffic flowing?) remains possible via
// SocksstubSetVerboseFlowLogs(true) — a future Settings toggle will
// surface it. Heartbeat + errors + lifecycle events are NOT gated and
// always show.
var verboseFlowLogs atomic.Bool

// IPA-D2 hybrid burst protection. Three-input OR trigger
// (accept-rate burst OR avail<12MiB OR kernel .critical). During the
// 5-second protect window, two-axis admission: rate.Limiter (120/s
// burst 24, Allow-not-Wait) AND pendingNew cap (64). Excess accepts
// are Close()d (RST → iOS app retry). Established flows untouched.
var (
	protectUntil int64 // atomic unix-nano; if > now → protect mode active

	// recoveryConfirmed defaults to 1 ("memory OK, no engage yet") so
	// that on cold start (before any engage) inProtect() returns false.
	// Cleared to 0 inside enterProtect() under protectMu on every
	// (re-)engage; set to 1 by MaybeReleaseProtect() after a fresh
	// avail≥18 MiB observation provided protectUntil has already elapsed.
	recoveryConfirmed int32 = 1

	pendingNew       int32 // atomic; in-flight DialContext during protect
	burstShedTotal   int64 // atomic
	burstEngageTotal int64 // atomic

	// accept-rate counters, only meaningful during protect detection.
	// Two sliding windows: 100 ms (cap=48) and 500 ms (cap=180).
	acceptTimes100 = newRingTimes(64)  // ring of unix-nanos, sized > worst-case 100 ms hits
	acceptTimes500 = newRingTimes(256) // ring sized > worst-case 500 ms hits
	acceptRateMu   sync.Mutex          // guards both rings

	burstLimiter = rate.NewLimiter(rate.Limit(120), 24) // active only in protect mode

	// protectMu guards the engage/release transitions in enterProtect()
	// and MaybeReleaseProtect() so they cannot interleave. Without this,
	// a concurrent MaybeReleaseProtect() could set recoveryConfirmed=1
	// using a stale "memory OK" observation that was made before a
	// fresh engage, causing release on next TTL expiry without any
	// post-engage avail≥18 MiB confirmation. The hot path (inProtect()
	// in acceptLoop) does NOT take this lock — it only does atomic
	// reads, so accept overhead is unchanged.
	protectMu sync.Mutex
)

const (
	pendingCap        = 64
	protectTTL        = 5 * time.Second
	burstWindow100    = 100 * time.Millisecond
	burstWindow500    = 500 * time.Millisecond
	burstThreshold100 = 48
	burstThreshold500 = 180
)

// ringTimes is a tiny lock-protected ring buffer of unix-nanos for
// counting how many events fell in the last N ms.
type ringTimes struct {
	buf  []int64
	head int
	n    int
}

func newRingTimes(cap int) *ringTimes { return &ringTimes{buf: make([]int64, cap)} }

func (r *ringTimes) addAndCountSince(now int64, since int64) int {
	// Push current event. Overwrites oldest if full (we only care about
	// the last `since` ns anyway).
	r.buf[r.head] = now
	r.head = (r.head + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
	cnt := 0
	for i := 0; i < r.n; i++ {
		if r.buf[i] >= since {
			cnt++
		}
	}
	return cnt
}

// enterProtect is the single engage point used by all three triggers
// (Swift kernel critical, Swift heartbeat avail<12MiB, Go accept-rate
// burst). It clears recoveryConfirmed=0 atomically with the protectUntil
// extension under protectMu, so any concurrent MaybeReleaseProtect()
// either runs entirely before or entirely after this engage.
func enterProtect(d time.Duration) {
	until := time.Now().Add(d).UnixNano()
	protectMu.Lock()
	defer protectMu.Unlock()
	old := atomic.LoadInt64(&protectUntil)
	if until <= old {
		return
	}
	atomic.StoreInt64(&protectUntil, until)
	// Always reset recovery confirmation on every (re-)engage. Done
	// under protectMu so the store is ordered with the protectUntil
	// extension — a concurrent MaybeReleaseProtect cannot leave
	// recoveryConfirmed=1 in front of this fresh engage.
	atomic.StoreInt32(&recoveryConfirmed, 0)
	// Count the engagement only when transitioning from inactive.
	if old < time.Now().UnixNano() {
		atomic.AddInt64(&burstEngageTotal, 1)
		rt.appendLog("warn: burst protection ENGAGED")
	}
}

func inProtect(now time.Time) bool {
	if now.UnixNano() < atomic.LoadInt64(&protectUntil) {
		return true
	}
	// TTL elapsed; only release if Swift has confirmed memory recovery.
	return atomic.LoadInt32(&recoveryConfirmed) == 0
}

// acceptBurstHit returns true if the accept-rate window has been exceeded.
// Updates both rings as a side effect.
func acceptBurstHit(now time.Time) bool {
	nowNs := now.UnixNano()
	acceptRateMu.Lock()
	defer acceptRateMu.Unlock()
	c100 := acceptTimes100.addAndCountSince(nowNs, nowNs-burstWindow100.Nanoseconds())
	c500 := acceptTimes500.addAndCountSince(nowNs, nowNs-burstWindow500.Nanoseconds())
	return c100 >= burstThreshold100 || c500 >= burstThreshold500
}

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

// EnterProtectMode is called from Swift on memory-pressure signals
// (kernel .critical or os_proc_available_memory < 12 MiB). The
// `millis` argument extends the protect window from now.
// gomobile binding exposes this to Swift as SocksstubEnterProtectMode(int).
//
// recoveryConfirmed is cleared inside enterProtect() under protectMu;
// no separate clear is needed here.
func EnterProtectMode(millis int) {
	if millis <= 0 {
		millis = int(protectTTL / time.Millisecond)
	}
	enterProtect(time.Duration(millis) * time.Millisecond)
}

// MaybeReleaseProtect is called from Swift's heartbeat when
// os_proc_available_memory() >= 18 MiB. Sets the recovery-confirmed
// flag so inProtect() can release once the protect TTL has elapsed.
//
// Held under protectMu so the store is ordered with concurrent
// enterProtect() engages; additionally gated on protectUntil being
// in the past so a stale "memory OK" observation made before a recent
// engage cannot apply to that fresh engage. While protectUntil is
// in the future, our observation is necessarily older than that
// engage and must be discarded; the next heartbeat tick (≤1 s later,
// once protectUntil has elapsed) will re-confirm if avail still ≥18 MiB.
//
// gomobile binding exposes this to Swift as SocksstubMaybeReleaseProtect().
func MaybeReleaseProtect() {
	protectMu.Lock()
	defer protectMu.Unlock()
	if time.Now().UnixNano() < atomic.LoadInt64(&protectUntil) {
		return
	}
	atomic.StoreInt32(&recoveryConfirmed, 1)
}

// BurstShedTotal / BurstEngageTotal / BurstActive expose counters for
// the Swift heartbeat log.
func BurstShedTotal() int64   { return atomic.LoadInt64(&burstShedTotal) }
func BurstEngageTotal() int64 { return atomic.LoadInt64(&burstEngageTotal) }
func BurstActive() int32 {
	if inProtect(time.Now()) {
		return 1
	}
	return 0
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
	startIdleEvictor(ctx) // IPA-D6: proactive idle eviction
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
		// IPA-Z7: re-introduce a client-side cap, this time at 200.
		//
		// History:
		//   IPA-F (50): too tight — 50 streams jammed by Roblox alone
		//               + Safari + YouTube → "multi-open blocks all".
		//   IPA-Z4 (0):  removed cap to honour server's 1000. Worked
		//               on Windows. ON iOS 50 MB jetsam this allowed
		//               Go's net/http2 to open hundreds of concurrent
		//               streams under speedtest fanout, each ~50-100 KB
		//               of read/write buffers + flow-control state →
		//               heap saturated GOMEMLIMIT (37 MB), GC thrashed
		//               (1655 cycles in 16 s, observed in IPA-Z6 log
		//               2026-05-05 13:07), iOS jetsam'd.
		//   IPA-Z7 (200): compromise — 4× the failing IPA-F value,
		//               plenty for realistic iOS workload (speedtest
		//               fanout 32 + Safari ~50 + Roblox 4-8 + YouTube
		//               16 ≈ ~100 active worst case), well below the
		//               desktop 1000 that explodes our heap. Memory
		//               cost ~16 MB worst case (200 × 80 KB), fits
		//               under our budget with headroom for Go runtime
		//               itself, hev, and Swift state.
		//
		//   IPA-A2 (1000): backfired. 1000 cap caused go.inuse=57 MB
		//               under speedtest. Per-stream cost on Go h2 +
		//               tamizdat is ~200-250 KB (recv buf 64 + send buf
		//               + header arena + goroutine stack + tamizdat
		//               per-flow state), not just the 64 KB recv buffer.
		//               At ~200 active streams that's 50 MB regardless
		//               of how small we make the window. iOS architectural
		//               ceiling is ~200-300 active streams in 50 MB
		//               jetsam, period.
		//   IPA-A3 (200): back to cap=200 (A1's speedtest survived this)
		//               but pair with vendor-x-net stream window 64 KiB.
		//   IPA-A9 (150): operator request after A7 still crashed under
		//               Roblox+YouTube combo. 150 × ~130 KB live per
		//               active stream = ~19 MiB peak instead of ~26 MiB
		//               at 200 — frees ~6-7 MiB headroom under jetsam.
		//               IPA-D8: REVERTED 8→150. D6 set this to 8 hoping
		//               to bound heap. With V2 mode (MaxTransports=2),
		//               total slots = 8 × 2 = 16 — insufficient for
		//               normal iOS multi-app combo. Result: every dial
		//               immediately failed with "pool at MaxTransports cap"
		//               error. Pool size doesn't fix memory; we need
		//               D7's bufio.Copy + nuclear close approach instead.
		MaxStreamsPerConn: 150,
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

	// IPA-A7: disable client-side realtime detector on iOS. Operator's
	// measurement: bulk vs lite shape-flip RTT difference is 1 ms (117
	// vs 116 ms) on this network — no user-perceptible benefit. The
	// detector's per-packet Observe under d.mu was the hottest mutex
	// at speedtest pps. Server-side classifier independently decides
	// realtime per its own packet timing — wire protocol unaffected.
	client.DisableRealtimeDetector()
	rt.appendLog("info: client realtime detector = DISABLED (iOS-local)")

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

// IPA-A8 fsync rate-limiter: was per-line fsync. Under YouTube/Roblox
// workload that's 10-50 fsync/sec on the App Group log file, which
// is real CPU + iowait on the data hot path. Now we sync at most
// once per 1 sec; a small lag in Swift's tail visibility is
// negligible vs the cost.
var lastSyncNano atomic.Int64

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
		// Rate-limit fsync to once per second.
		now := time.Now().UnixNano()
		last := lastSyncNano.Load()
		if now-last >= int64(time.Second) && lastSyncNano.CompareAndSwap(last, now) {
			_ = sink.Sync()
		}
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
		now := time.Now()

		// Detect accept-rate burst. Side-effect updates rings.
		if acceptBurstHit(now) {
			enterProtect(protectTTL)
		}

		// Fast path when not in protect mode — byte-identical to A9.
		if !inProtect(now) {
			n := rt.connsTotal.Add(1)
			rt.connsActive.Add(1)
			flowLogf("info: accept #%d from %s", n, c.RemoteAddr())
			// IPA-D6: register flow for proactive idle eviction.
			flowCtx, flowCancel := context.WithCancel(ctx)
			fs := &flowState{conn: c, cancel: flowCancel, createdNano: time.Now().UnixNano()}
			fs.lastActiveNano.Store(fs.createdNano)
			flowRegistry.Store(n, fs)
			go func(client net.Conn, idx uint64) {
				defer client.Close()
				defer rt.connsActive.Add(-1)
				defer flowRegistry.Delete(idx)
				defer flowCancel()
				handleSocks(flowCtx, client, idx)
			}(c, n)
			continue
		}

		// Protect mode: rate-limit (Allow, not Wait) and cap pending.
		if !burstLimiter.Allow() {
			atomic.AddInt64(&burstShedTotal, 1)
			_ = c.Close()
			continue
		}
		if atomic.AddInt32(&pendingNew, 1) > pendingCap {
			atomic.AddInt32(&pendingNew, -1)
			atomic.AddInt64(&burstShedTotal, 1)
			_ = c.Close()
			continue
		}
		n := rt.connsTotal.Add(1)
		rt.connsActive.Add(1)
		flowLogf("info: accept #%d from %s (protect mode)", n, c.RemoteAddr())
		// IPA-D6: register protect-mode flow too.
		flowCtx, flowCancel := context.WithCancel(ctx)
		fs := &flowState{conn: c, cancel: flowCancel, createdNano: time.Now().UnixNano()}
		fs.lastActiveNano.Store(fs.createdNano)
		flowRegistry.Store(n, fs)
		go func(client net.Conn, idx uint64) {
			defer atomic.AddInt32(&pendingNew, -1)
			defer client.Close()
			defer rt.connsActive.Add(-1)
			defer flowRegistry.Delete(idx)
			defer flowCancel()
			handleSocks(flowCtx, client, idx)
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
	relay(client, upstream, idx)
	flowLogf("info: conn#%d closed (lifetime %dms)", idx, time.Since(dialStart).Milliseconds())
}

func sendReply(client net.Conn, code byte) error {
	// Standard 10-byte reply: bound addr 0.0.0.0:0, atyp ipv4.
	reply := []byte{socksVersion5, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := client.Write(reply)
	return err
}

// dialUpstream is the swap-point: stage 1 = direct, stage 2 = samizdat.
// IPA-A1: app-hint Tier 3 removed (PacketBridge gone). Server's
// Tier 1 (port whitelist) + Tier 2 (cadence) carry the realtime
// classifier without us.
func dialUpstream(ctx context.Context, dest string) (net.Conn, error) {
	rt.mu.Lock()
	client := rt.samizdatClient
	rt.mu.Unlock()
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
// IPA-A5 (Phase A from analyst review 2026-05-05): the per-target
// PacketConn map (`pcs`) is bounded with both a hard cap and an idle
// timeout. Without these, YouTube QUIC playback on iOS opens hundreds
// of unique (host, port) destinations across googlevideo edges, ad
// servers and telemetry endpoints — each entry costs ~80-120 KB
// (64 KiB scratch buf + reverse goroutine + samizdat
// udpFramedPacketConn + h2 stream window) and never gets evicted in
// the original code (only freed on outer FWD_UDP TCP close, which
// lasts the whole tunnel session). 9-minute YouTube → ~300 entries
// → ~30 MiB silent leak → iOS jetsam.
//
// Now: hard cap 128 entries (LRU eviction), per-entry idle timer
// (60 s, reset on every forward/reverse datagram), lazy sweep of
// expired entries on each forward datagram.
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
		atyp        byte         // remember the atyp for the reverse frame header
		addrEncoded []byte       // pre-encoded addr+port bytes (without atyp)
		lastActive  atomic.Int64 // unix nanos, reset on every forward/reverse activity
	}
	const (
		fwdUDPMaxEntries = 128                // hard cap on pcs map
		fwdUDPIdleNanos  = 60 * 1_000_000_000 // 60 s idle → evict
	)
	var (
		pcMu      sync.Mutex
		pcs       = make(map[pcKey]*pcEntry, fwdUDPMaxEntries)
		writeMu   sync.Mutex // serialize TCP writes back to hev
		datagrams atomic.Uint64
		evictions atomic.Uint64
	)

	// closeEntry tears down a pcEntry: closes the underlying samizdat
	// UDP-over-CONNECT (which propagates to server, h2 stream RST), then
	// the reverse goroutine exits naturally on its next ReadFrom err.
	// Caller must hold pcMu (the entry should already be removed from
	// the map before close to prevent double-close races with the
	// reverse goroutine path).
	closeEntry := func(e *pcEntry) {
		_ = e.pc.Close()
	}

	closeAll := func() {
		pcMu.Lock()
		for _, e := range pcs {
			closeEntry(e)
		}
		pcs = nil
		pcMu.Unlock()
	}
	defer closeAll()

	// Sweep entries idle longer than fwdUDPIdleNanos. Caller holds pcMu.
	sweepIdleLocked := func(nowNano int64) {
		for k, e := range pcs {
			if nowNano-e.lastActive.Load() > fwdUDPIdleNanos {
				delete(pcs, k)
				closeEntry(e)
				evictions.Add(1)
			}
		}
	}

	// Evict the single oldest entry to make room for a new one.
	// Caller holds pcMu.
	evictOldestLocked := func() {
		var oldestKey pcKey
		var oldestNano int64 = -1
		for k, e := range pcs {
			la := e.lastActive.Load()
			if oldestNano < 0 || la < oldestNano {
				oldestNano = la
				oldestKey = k
			}
		}
		if oldestNano >= 0 {
			e := pcs[oldestKey]
			delete(pcs, oldestKey)
			closeEntry(e)
			evictions.Add(1)
		}
	}

	startReverse := func(key pcKey, e *pcEntry) {
		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, _, err := e.pc.ReadFrom(buf)
				if err != nil {
					return
				}
				e.lastActive.Store(time.Now().UnixNano())
				// Frame: datlen | hdrlen | atype | addr | port | data
				// IPA-A5: write framing header and payload via separate
				// Write calls under writeMu, instead of allocating a
				// fresh frame []byte per datagram. At YouTube/voice
				// rates (1k-3k pps) the old per-pkt allocation produced
				// 1-3 MB/s of GC garbage.
				addrLen := len(e.addrEncoded) // includes port (no atyp)
				hdrLen := 3 + 1 + addrLen     // 3 = datlen+hdrlen; +1 for atyp
				var hdrBuf [4]byte
				binary.BigEndian.PutUint16(hdrBuf[0:2], uint16(n))
				hdrBuf[2] = byte(hdrLen)
				hdrBuf[3] = e.atyp

				writeMu.Lock()
				_, werr := client.Write(hdrBuf[:])
				if werr == nil {
					_, werr = client.Write(e.addrEncoded)
				}
				if werr == nil {
					_, werr = client.Write(buf[:n])
				}
				writeMu.Unlock()
				if werr != nil {
					return
				}
			}
		}()
	}

	// Periodic idle sweep so entries that go silent (closed peer with
	// no further activity) get reaped even when the map isn't full.
	sweepTicker := time.NewTicker(15 * time.Second)
	defer sweepTicker.Stop()
	go func() {
		for {
			select {
			case <-subCtx.Done():
				return
			case t := <-sweepTicker.C:
				pcMu.Lock()
				sweepIdleLocked(t.UnixNano())
				pcMu.Unlock()
			}
		}
	}()

	// Forward path: read framed datagrams from hev, look up / open
	// PacketConn for the target, write the payload.
	for {
		var hdr [3]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			flowLogf("info: udp#%d session end (%d datagrams, %d evictions)", idx, datagrams.Load(), evictions.Load())
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
		nowNano := time.Now().UnixNano()
		pcMu.Lock()
		e, ok := pcs[key]
		if ok {
			e.lastActive.Store(nowNano)
		} else {
			// Entry not present — open new tunnel. First make room.
			if len(pcs) >= fwdUDPMaxEntries {
				sweepIdleLocked(nowNano)
				if len(pcs) >= fwdUDPMaxEntries {
					evictOldestLocked()
				}
			}
			pcMu.Unlock()
			// Dial outside the lock — TCP+uTLS+H2 setup is slow.
			// IPA-K: 5s was too tight for slow cellular. 20s gives the
			// underlying samizdat.DialUDP enough headroom for cold-cache
			// transport setup (TCP dial + uTLS handshake + H2 settings).
			dialCtx, dialCancel := context.WithTimeout(subCtx, 20*time.Second)
			pc, derr := dialUpstreamUDP(dialCtx, net.JoinHostPort(host, strconv.Itoa(int(port))))
			dialCancel()
			if derr != nil {
				rt.appendLog(fmt.Sprintf("warn: udp#%d dial %s:%d: %v", idx, host, port, derr))
				continue
			}
			pcMu.Lock()
			// Re-check after re-acquiring lock — another goroutine may
			// have raced us to dial the same key (unlikely with single
			// forward loop, but cheap to check).
			if existing, raced := pcs[key]; raced {
				_ = pc.Close()
				e = existing
				e.lastActive.Store(nowNano)
			} else {
				e = &pcEntry{
					pc:          pc,
					atyp:        atyp,
					addrEncoded: addrSection[1:],
				}
				e.lastActive.Store(nowNano)
				pcs[key] = e
				startReverse(key, e)
				flowLogf("info: udp#%d new target %s:%d (active=%d)", idx, host, port, len(pcs))
			}
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

// IPA-D5: pooled relay buffers. Previously each goroutine allocated a
// fresh 16 KiB buffer, so under burst (e.g. 16 Speedtest streams)
// every accept added 32 KiB live to the heap until GC. With a pool
// the live buffer count = max simultaneously-in-CopyBuffer goroutines,
// not max accepted goroutines. On 16-flow Speedtest steady-state where
// not every flow is in copy at once this saves ~5-10 MiB.
//
// Pool buffers are GCable — sync.Pool allows runtime to free entries
// during GC pressure, so we never permanently retain memory.
var relayBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 16*1024)
		return &buf
	},
}

func getRelayBuf() *[]byte { return relayBufPool.Get().(*[]byte) }
func putRelayBuf(b *[]byte) { relayBufPool.Put(b) }

// IPA-D7: relay using sing-box's bufio.Copy with `with_low_memory` build
// tag. This forces all copies through copyWaitWithPool — pool-managed
// refcounted buffers from sing/common/buf/alloc.go (power-of-2 sync.Pool
// from 64 B to 64 KiB). With the build tag, BufferSize=16 KiB and
// LowMemory const = true so even non-WaitReader sources go through pool.
//
// This is the EXACT pattern sing-box-for-apple uses on iOS to survive
// the 50 MiB jetsam cap. We copied verbatim because (per operator memory
// rule "find what works > rollback") working open-source projects on
// the same platform under same constraints have already solved this.
func relay(a, b net.Conn, idx uint64) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = singBufio.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = singBufio.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
}

// CloseAllFlows force-closes every registered flow's local SOCKS5 conn.
//
// IPA-D9 fix: removed fs.cancel() from the original D7 implementation.
// Cancel propagated into tamizdat client's in-flight DialContext via
// context tree, killing the upstream H/2 transport and triggering a
// "http2: client connection lost" cascade lasting ~40 seconds visible
// to user (Roblox 277, YouTube stall, etc). Just closing the local
// conn is enough — the goroutine sees EOF on the next CopyBuffer
// iteration and exits naturally; tamizdat's transport pool stays alive.
//
// gomobile binding exposes this as SocksstubCloseAllFlows().
func CloseAllFlows() int32 {
	closed := int32(0)
	flowRegistry.Range(func(k, v any) bool {
		fs := v.(*flowState)
		_ = fs.conn.Close()
		closed++
		return true
	})
	if closed > 0 {
		rt.appendLog(fmt.Sprintf("warn: nuclear close — %d flows terminated under memory pressure", closed))
	}
	debug.FreeOSMemory()
	return closed
}

// IPA-D9: heap profiling endpoint. Swift passes a file path (App Group
// container so it survives across extension/main-app and is reachable
// via Files app). Go writes the gzipped pprof profile there.
//
// Trigger: Swift heartbeat calls SocksstubWriteHeapProfile(path) right
// before invoking SocksstubCloseAllFlows on memory pressure — captures
// the heap state at the exact moment iOS thinks we're critical, which
// is the most informative snapshot.
//
// Analysis: copy file off device (Files app or Telegram uploader),
// run `go tool pprof heap-<ts>.pb.gz` to find what eats per-flow memory.
//
// Returns empty string on success, error message on failure.
func WriteHeapProfile(path string) string {
	// Force GC first so unreachable allocations don't pollute the heap profile.
	runtime.GC()
	f, err := os.Create(path)
	if err != nil {
		return fmt.Sprintf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Sprintf("write profile: %v", err)
	}
	rt.appendLog(fmt.Sprintf("info: heap profile written to %s", path))
	return ""
}

// WriteGoroutineProfile dumps current goroutine stacks. Useful for
// diagnosing goroutine leaks.
func WriteGoroutineProfile(path string) string {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Sprintf("create %s: %v", path, err)
	}
	defer f.Close()
	p := pprof.Lookup("goroutine")
	if p == nil {
		return "no goroutine profile available"
	}
	if err := p.WriteTo(f, 2); err != nil { // 2 = full stacks
		return fmt.Sprintf("write profile: %v", err)
	}
	rt.appendLog(fmt.Sprintf("info: goroutine profile written to %s", path))
	return ""
}
