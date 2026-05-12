// IPA-D21: real-internet ping prober for the iOS main-screen shield.
//
// Replaces the internal H/2 PING-based RTT exporter (RTTLastMs et al.) with
// an end-to-end HTTP HEAD request through the samizdat tunnel. The
// previous metric measured server-side health (H/2 keepalive RTT); this
// one tells the user whether the real internet works through the proxy —
// which is what they actually want to know.
//
// Design:
//
//   - Single background goroutine per samizdat client lifetime.
//   - Every 10 s: HTTP HEAD via http.Client whose Transport.DialContext
//     calls samizdat.Client.DialContext directly (NOT via the SOCKS5
//     loopback — direct measurement, dodges loopback overhead and avoids
//     re-entering our own listener).
//   - 5 s per-probe timeout.
//   - Failed state := 2+ consecutive misses (single transient drop never
//     trips it).
//
// Lifecycle: SetSamizdatConfig() in socksstub.go starts a fresh prober
// after the new client is in place and stops the old one. In-flight
// HTTP requests against the old client just fail naturally when the
// client closes — we don't try to coordinate.
//
// Probe URL is user-configurable via SetPingProbeURL (called from Swift
// after reading App Group UserDefaults `tamizdat.pingProbeURL`).
// Default: http://www.gstatic.com/generate_204 — Google's connectivity
// probe, 204 No Content, ~tiny payload, well-known and stable.

package socksstub

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	samizdat "github.com/detectqq/tamizdat"
)

const (
	defaultPingProbeURL = "http://www.gstatic.com/generate_204"
	// IPA-D25 fix7: dynamic cadence. When the iOS main app is in the
	// foreground (signalled by its 500ms status-RPC heartbeat), probe
	// every 3s so the UI feels live. When backgrounded (no heartbeat
	// for >5s), drop to 30s for battery — user can't see it anyway.
	pingProbeIntervalFG = 3 * time.Second
	pingProbeIntervalBG = 30 * time.Second
	foregroundStaleAfter = 5 * time.Second
	// IPA-D27: 5s → 3s. Faster failure detection so the shield can
	// flip to red ("Proxy unreachable") within ~6-8s of connecting
	// when the proxy is unreachable, instead of operator seeing a
	// fake green for ~20s.
	pingProbeTimeout = 3 * time.Second
	pingFailedThreshold = 2 // consecutive misses to enter Failed state
)

// lastForegroundPollAtNanos is bumped to time.Now().UnixNano() every
// time Swift calls NoteForegroundPoll (= every status-RPC tick while
// the user is watching the screen). The prober loop checks this to
// decide its cadence.
var lastForegroundPollAtNanos atomic.Int64

// NoteForegroundPoll is the foreground heartbeat from Swift. Called
// once per 500ms status RPC fetch in TamizdatStatusStore.poll(). The
// ping prober uses this to switch between fast (foreground) and slow
// (background) cadence.
//
// Exported for gomobile binding as SocksstubNoteForegroundPoll().
func NoteForegroundPoll() {
	lastForegroundPollAtNanos.Store(time.Now().UnixNano())
}

// currentPingCadence returns the cadence appropriate for the current
// foreground/background state.
func currentPingCadence() time.Duration {
	last := lastForegroundPollAtNanos.Load()
	if last == 0 {
		return pingProbeIntervalBG
	}
	if time.Since(time.Unix(0, last)) > foregroundStaleAfter {
		return pingProbeIntervalBG
	}
	return pingProbeIntervalFG
}

// pingProberState holds the live counters for the ping prober. Lives in
// the package-global rt area; accessed via the proberMu mutex around
// lifecycle swap, and atomics for the snapshot fields.
type pingProberState struct {
	lastMs           atomic.Int64 // last successful latency in ms; -1 if no success ever
	ok               atomic.Bool  // last probe ok (true) or not
	consecutiveFails atomic.Int32 // 0 if last probe was ok; counts consecutive misses otherwise
	lastProbedAt     atomic.Int64 // unix nanos of last probe completion; 0 if never probed
}

var (
	proberMu      sync.Mutex
	proberCancel  context.CancelFunc // cancels the current goroutine; nil if no prober running
	proberURL     atomic.Value       // string — current probe URL (set on init, updated by SetPingProbeURL)
	proberState   = &pingProberState{}
)

func init() {
	// Initial: no success ever.
	proberState.lastMs.Store(-1)
	proberURL.Store(defaultPingProbeURL)
}

// SetPingProbeURL updates the URL the prober pings. Empty falls back to
// the default. Safe to call from Swift at any time — the next probe
// cycle picks up the new value. Does not restart the prober.
//
// Exported for gomobile binding as SocksstubSetPingProbeURL(string).
func SetPingProbeURL(u string) {
	if u == "" {
		u = defaultPingProbeURL
	}
	// Cheap validation: must parse as URL with non-empty host. If invalid,
	// fall back to default and log it so the user sees what happened.
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		rt.appendLog(fmt.Sprintf("warn: ping probe URL %q invalid (%v) — using default", u, err))
		u = defaultPingProbeURL
	}
	proberURL.Store(u)
	rt.appendLog(fmt.Sprintf("info: ping probe URL = %s", u))
}

// currentPingProbeURL returns the current target. Never empty.
func currentPingProbeURL() string {
	v, _ := proberURL.Load().(string)
	if v == "" {
		return defaultPingProbeURL
	}
	return v
}

// PingSnapshot is the gomobile-friendly read-only view of the prober's
// most recent state. Built fresh per call (no shared mutable state
// crosses the binding boundary).
type PingSnapshot struct {
	LastMs       int64  // last successful latency in ms; -1 if no success ever
	OK           bool   // last probe succeeded
	Failed       bool   // 2+ consecutive misses (the UI "failed" state)
	LastProbedAt int64  // unix nanos of last probe completion; 0 if never probed
	URL          string // currently-configured probe URL (echoed back for debugging)
}

// PingProbeSnapshot returns the current state of the ping prober. Safe
// to call from Swift on the UI thread; all reads are bounded atomic
// loads.
//
// Exported for gomobile binding as SocksstubPingProbeSnapshot().
func PingProbeSnapshot() *PingSnapshot {
	return &PingSnapshot{
		LastMs:       proberState.lastMs.Load(),
		OK:           proberState.ok.Load(),
		Failed:       proberState.consecutiveFails.Load() >= pingFailedThreshold,
		LastProbedAt: proberState.lastProbedAt.Load(),
		URL:          currentPingProbeURL(),
	}
}

// startPingProber stops any previous prober and starts a new one bound
// to the given samizdat client. Called from SetSamizdatConfig under
// rt.mu after the new client is installed. The supplied client is
// closed-over here; if it gets replaced, this goroutine's in-flight
// dial fails naturally and the next tick re-reads via the bound
// reference (no, we don't re-read — we stop+restart the prober on
// every config swap, see stopPingProber).
func startPingProber(client *samizdat.Client) {
	proberMu.Lock()
	defer proberMu.Unlock()

	// Stop any prior prober.
	if proberCancel != nil {
		proberCancel()
		proberCancel = nil
	}
	if client == nil {
		return
	}

	// IPA-D27: reset session state so a fresh client starts as
	// "unvalidated" — Swift UI uses lastMs < 0 to mean "no successful
	// probe yet this session" and shows "Connecting…" until the first
	// real probe lands. Without this reset, stale ping value from the
	// previous client would briefly paint the shield green before the
	// new client has actually validated.
	proberState.lastMs.Store(-1)
	proberState.ok.Store(false)
	proberState.consecutiveFails.Store(0)
	proberState.lastProbedAt.Store(0)
	// Also reset the auto-rewire throttle so the next miss-cascade can
	// fire immediately if the new client also can't reach the probe.
	lastRewireRequestedNanos.Store(0)

	ctx, cancel := context.WithCancel(context.Background())
	proberCancel = cancel
	go runPingProbeLoop(ctx, client)
	rt.appendLog("info: ping prober started (state reset)")
}

// stopPingProber cancels the running prober (if any). Called on
// disconnect (SetSamizdatConfig("")) — leaves the snapshot fields at
// their last values so the UI can keep displaying the last known ping
// briefly before the lamp switches to "— offline —".
func stopPingProber() {
	proberMu.Lock()
	defer proberMu.Unlock()
	if proberCancel != nil {
		proberCancel()
		proberCancel = nil
		rt.appendLog("info: ping prober stopped")
	}
}

// runPingProbeLoop is the goroutine body. Cadence is dynamic — 3 s
// while the main app is in the foreground (Swift hits NoteForegroundPoll
// every 500 ms status RPC), 30 s when backgrounded. Each tick re-reads
// the configured URL so live URL changes via SetPingProbeURL take effect
// on the next probe without restarting.
func runPingProbeLoop(ctx context.Context, client *samizdat.Client) {
	// Fire one probe immediately so the first sample shows up on the
	// shield within a few seconds of connect.
	probeOnce(ctx, client)

	// Dynamic cadence: use time.Timer instead of Ticker so we can
	// re-arm with the current cadence each cycle (3s FG / 30s BG).
	for {
		next := currentPingCadence()
		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			probeOnce(ctx, client)
		}
	}
}

// probeOnce performs one HTTP HEAD through the samizdat tunnel and
// updates the shared snapshot. Errors and non-2xx/3xx responses both
// count as "miss".
func probeOnce(ctx context.Context, client *samizdat.Client) {
	target := currentPingProbeURL()
	u, err := url.Parse(target)
	if err != nil {
		recordMiss()
		rt.appendLog(fmt.Sprintf("warn: ping probe parse %q: %v", target, err))
		return
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	hostport := net.JoinHostPort(host, port)

	// http.Client with a Transport whose DialContext goes through the
	// samizdat client directly. We rebuild this per probe (cheap — no
	// connection caching beyond the probe itself) so context cancellation
	// + per-probe timeout work cleanly.
	transport := &http.Transport{
		DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
			// network/address args ignored: we always dial the URL host:port
			// through the samizdat tunnel.
			return client.DialContext(c, "tcp", hostport)
		},
		DialTLSContext: func(c context.Context, _, _ string) (net.Conn, error) {
			raw, derr := client.DialContext(c, "tcp", hostport)
			if derr != nil {
				return nil, derr
			}
			tlsConn := tls.Client(raw, &tls.Config{
				ServerName: host,
				// Probe URL is user-configurable; default is google's
				// connectivity probe (gstatic.com, public CA-signed).
				// Standard verification is fine.
			})
			if err := tlsConn.HandshakeContext(c); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		// Don't reuse keep-alives across probes — we want each probe to
		// measure a clean dial + request through our tunnel.
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}
	hc := &http.Client{
		Transport: transport,
		Timeout:   pingProbeTimeout,
		// Don't follow redirects — gstatic.com/generate_204 is intentionally
		// a 204; any redirect would inflate the timing and possibly leak
		// through our tunnel a destination the user didn't pick.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	probeCtx, cancel := context.WithTimeout(ctx, pingProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, target, nil)
	if err != nil {
		recordMiss()
		rt.appendLog(fmt.Sprintf("warn: ping probe newrequest: %v", err))
		return
	}
	// Small, generic UA — don't expose iOS-specific bits in the tunnelled
	// probe. gstatic happily serves any UA.
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	start := time.Now()
	resp, err := hc.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		recordMiss()
		// One-line warn, no stack — these are routine on flaky networks.
		rt.appendLog(fmt.Sprintf("warn: ping probe %s failed after %dms: %v", target, elapsed.Milliseconds(), err))
		return
	}
	_ = resp.Body.Close()

	// Treat any 2xx or 3xx as success. gstatic returns 204; cloudflare's
	// generate_204 also 204; some captive-portal probes use 200. 4xx/5xx
	// = network somewhere along the path failed.
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		recordSuccess(elapsed)
	} else {
		recordMiss()
		rt.appendLog(fmt.Sprintf("warn: ping probe %s status %d (treating as miss)", target, resp.StatusCode))
	}
}

func recordSuccess(latency time.Duration) {
	ms := latency.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	proberState.lastMs.Store(ms)
	proberState.ok.Store(true)
	proberState.consecutiveFails.Store(0)
	proberState.lastProbedAt.Store(time.Now().UnixNano())
}

func recordMiss() {
	proberState.ok.Store(false)
	fails := proberState.consecutiveFails.Add(1)
	proberState.lastProbedAt.Store(time.Now().UnixNano())
	// Keep lastMs at its last successful value so the UI can show "last
	// good latency" even while the shield turns yellow. If you'd rather
	// blank it on miss, set proberState.lastMs.Store(-1) here.

	// IPA-D26: when failures pile up (>= 2 consecutive), request a
	// rewireUpstream from Swift side even though NWPathMonitor hasn't
	// fired. Catches the case where wifi is dying but iOS hasn't yet
	// failed over to LTE — the prober sees upstream is unreachable and
	// tells Swift to rebuild the client over whatever the current
	// system default route is. Throttled to once per 15 s to avoid
	// thrashing during real outage.
	if fails >= 2 {
		maybeRequestRewire()
	}
}

// RewireRequester is the gomobile-bound interface Swift implements to
// receive auto-rewire requests from the ping prober.
type RewireRequester interface {
	RequestRewire()
}

var (
	rewireRequester          atomic.Value // RewireRequester
	lastRewireRequestedNanos atomic.Int64
)

// SetRewireRequester registers Swift's rewire callback. Called once
// from PacketTunnelProvider during startTunnel.
//
// Exported for gomobile binding as SocksstubSetRewireRequester(r).
func SetRewireRequester(r RewireRequester) {
	rewireRequester.Store(r)
}

func maybeRequestRewire() {
	const minInterval = 15 * time.Second
	last := lastRewireRequestedNanos.Load()
	if last != 0 && time.Since(time.Unix(0, last)) < minInterval {
		return
	}
	v := rewireRequester.Load()
	if v == nil {
		return
	}
	cb, ok := v.(RewireRequester)
	if !ok || cb == nil {
		return
	}
	lastRewireRequestedNanos.Store(time.Now().UnixNano())
	rt.appendLog("info: ping prober → auto-rewire requested (consecutive fails)")
	go cb.RequestRewire()
}

