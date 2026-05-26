package socksstub

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/detectqq/tamizdat/wgturnclient"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// VK TURN upstream — opt-in transport that wraps WireGuard inside DTLS
// inside VK call-relay traffic. This file is the gomobile-safe bridge
// between the Go runtime running in the main app (where SocksStub
// lives) and the Swift PacketTunnelProvider, which discovers the
// upstream's lifecycle through these exported strings/ints.
//
// Why the Go side owns the lifecycle: WireGuard config negotiation
// (GETCONF), the dispatcher, and the 12 DTLS sessions are already
// implemented in the wgturnclient library — Swift cannot drive those
// loops because gomobile cannot expose Go goroutines back to it.
//
// Why we never return *Runner to Swift: gomobile constrains return
// types to string/int/int64/bool/[]byte. Errors travel back as
// strings: an empty string means success.

var (
	vkturnRunner     *wgturnclient.Runner
	vkturnCancel     context.CancelFunc
	vkturnWGConfig   atomic.Pointer[string]
	vkturnStats      atomic.Pointer[string]
	vkturnErr        atomic.Pointer[string]
	vkturnNet        atomic.Pointer[netstack.Net]
	vkturnRunning    atomic.Bool
	vkturnAttachOnce sync.Once
	vkturnAttachStop func()
	vkturnMu         sync.Mutex
)

// StartVKTurnUpstream starts the VK TURN upstream. On success it returns "".
// On error it returns the error message. It waits up to 15 seconds for
// GETCONF before declaring "GETCONF timeout".
func StartVKTurnUpstream(credsJSON string, peerAddr string, wgPassword string, deviceID string, listenPort int) string {
	vkturnMu.Lock()
	if vkturnRunning.Load() {
		vkturnMu.Unlock()
		return "already running"
	}

	creds, err := parseVKTurnCredsJSON(credsJSON)
	if err != nil {
		vkturnMu.Unlock()
		return "credsJSON: " + err.Error()
	}

	resetVKTurnAtomicsLocked()
	vkturnAttachOnce = sync.Once{}

	// Pick transport from the first TURN server's metadata when the v2
	// wire shape is present; otherwise default to UDP (legacy
	// behaviour). VK has shipped both UDP and TCP-only relays, and
	// hard-forcing UDP against a TCP-only relay produces the
	// "Allocate: timeout" path users see on long-lived sessions.
	useUDP := shouldUseUDP(creds)

	runner, err := wgturnclient.New(wgturnclient.Config{
		Listen:         fmt.Sprintf("127.0.0.1:%d", listenPort),
		PeerAddr:       peerAddr,
		Workers:        12,
		UseUDP:         useUDP,
		DeviceID:       deviceID,
		ConnPassword:   wgPassword,
		PreloadedCreds: creds,
		OnConfig: func(conf string) {
			vkturnWGConfig.Store(&conf)
		},
	})
	if err != nil {
		vkturnMu.Unlock()
		return err.Error()
	}

	ctx, cancel := context.WithCancel(context.Background())
	vkturnRunner = runner
	vkturnCancel = cancel
	vkturnRunning.Store(true)
	storeVKTurnStats(0, true)
	vkturnMu.Unlock()

	go func() {
		err := runner.Start(ctx)

		vkturnMu.Lock()
		defer vkturnMu.Unlock()

		// Concurrency: a fresh Start() might have replaced vkturnRunner
		// while we were running; only clean up if we're still the owner.
		if vkturnRunner != runner {
			return
		}
		if err != nil {
			errText := err.Error()
			vkturnErr.Store(&errText)
		}
		stopVKTurnAttachLocked()
		vkturnRunning.Store(false)
		storeVKTurnStats(0, false)
		vkturnRunner = nil
		vkturnCancel = nil
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if p := vkturnWGConfig.Load(); p != nil {
			if !vkturnRunning.Load() {
				return "not running"
			}

			var res *wgturnclient.AttachResult
			var attachErr error
			vkturnAttachOnce.Do(func() {
				res, attachErr = runner.AttachWireGuardUserspace(*p)
			})
			if attachErr != nil {
				cancel()
				runner.Shutdown()
				return "wg attach: " + attachErr.Error()
			}
			if res != nil {
				vkturnMu.Lock()
				if vkturnRunner != runner || !vkturnRunning.Load() {
					vkturnMu.Unlock()
					res.Stop()
					return "not running"
				}
				vkturnNet.Store(res.Net)
				vkturnAttachStop = res.Stop
				vkturnMu.Unlock()
			}
			return ""
		}
		if p := vkturnErr.Load(); p != nil {
			return *p
		}
		if !vkturnRunning.Load() {
			return "not running"
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	runner.Shutdown()
	return "GETCONF timeout"
}

// UpdateVKTurnCreds swaps fresh credentials into the running runner so
// the next worker-group rotation tick uses them for TURN Allocate.
// Returns "" on success, "not running" when no runner is alive, or a
// parser error message when credsJSON is malformed.
//
// Why this exists: Config.PreloadedCreds is consumed once when the
// runner starts. Credentials live ~3600 s, but workers rotate every
// `lifetime - 120` s. Without a live update path the second rotation
// (about 58 min into the session) tries to allocate against expired
// creds and gets 401, killing the upstream. The Swift heartbeat in
// TURNCredsRefresher (5-min cadence) re-fetches before expiry and
// calls this exported func to publish the fresh snapshot.
//
// Concurrency: the worker loop calls preloadedCreds.Load() under
// groupAuthMutex. We use atomic.Pointer.Store here too so the swap
// is race-free without holding the mutex.
func UpdateVKTurnCreds(credsJSON string) string {
	if !vkturnRunning.Load() {
		return "not running"
	}
	creds, err := parseVKTurnCredsJSON(credsJSON)
	if err != nil {
		return "credsJSON: " + err.Error()
	}
	vkturnMu.Lock()
	runner := vkturnRunner
	vkturnMu.Unlock()
	if runner == nil {
		return "not running"
	}
	runner.UpdatePreloadedCreds(creds)
	return ""
}

// StopVKTurnUpstream stops the in-flight runner. Idempotent.
func StopVKTurnUpstream() {
	vkturnMu.Lock()
	defer vkturnMu.Unlock()

	if !vkturnRunning.Load() && vkturnRunner == nil && vkturnAttachStop == nil {
		resetVKTurnAtomicsLocked()
		return
	}
	if vkturnCancel != nil {
		vkturnCancel()
	}
	if vkturnRunner != nil {
		vkturnRunner.Shutdown()
	}
	vkturnRunner = nil
	vkturnCancel = nil
	stopVKTurnAttachLocked()
	resetVKTurnAtomicsLocked()
}

// TURNUpstreamWGConfig returns the latest WireGuard config text delivered
// by the server (the [Interface]/[Peer] block), or "" if not yet received.
func TURNUpstreamWGConfig() string {
	if !vkturnRunning.Load() {
		return ""
	}
	if p := vkturnWGConfig.Load(); p != nil {
		return *p
	}
	return ""
}

// TURNUpstreamStatsJSON returns the latest stats snapshot as a single-line
// JSON string. Empty string if not running.
func TURNUpstreamStatsJSON() string {
	if !vkturnRunning.Load() {
		return ""
	}
	storeVKTurnStats(0, true)
	if p := vkturnStats.Load(); p != nil {
		return *p
	}
	return ""
}

// TURNUpstreamRunning reports whether the VK TURN runner goroutine is alive.
func TURNUpstreamRunning() bool {
	return vkturnRunning.Load()
}

// TURNUpstreamLastError returns the last VK/wgturn runner error, if any. The
// value is intentionally a short diagnostic string; credentials JSON and TURN
// passwords are never stored here.
func TURNUpstreamLastError() string {
	if p := vkturnErr.Load(); p != nil {
		return *p
	}
	return ""
}

// VKTurnNetstack returns the userspace WireGuard netstack the upstream
// is currently bound to, or nil if there is none. Callers route every
// TCP/UDP dial through this stack — its underlying packets traverse
// 127.0.0.1:<wgturn relay port> → DTLS+TURN → VK relay → server.
//
// Not gomobile-exported (returns a struct pointer), only the Go callers
// in this same module use it.
func VKTurnNetstack() *netstack.Net {
	return vkturnNet.Load()
}

// stopVKTurnAttachLocked tears down the userspace WG + netstack the
// previous Start built. MUST be called with vkturnMu held.
func stopVKTurnAttachLocked() {
	if vkturnAttachStop != nil {
		vkturnAttachStop()
		vkturnAttachStop = nil
	}
	vkturnNet.Store(nil)
}

// turnServerWire is the v2 wire shape for a single TURN server
// entry. Swift writes this through TURNCredsStore.vkCredsAsJSON; the
// older `turn_servers` []string is still emitted alongside for
// backward compatibility with any extension build still on the v1
// schema.
type turnServerWire struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Scheme    string `json:"scheme"`
	Transport string `json:"transport"`
}

func parseVKTurnCredsJSON(credsJSON string) (*wgturnclient.Credentials, error) {
	var wire struct {
		Username      string           `json:"username"`
		Password      string           `json:"password"`
		TurnServers   []string         `json:"turn_servers"`
		TurnServersV2 []turnServerWire `json:"turn_servers_v2"`
		LifetimeSec   int              `json:"lifetime_sec"`
	}
	if err := json.Unmarshal([]byte(credsJSON), &wire); err != nil {
		return nil, err
	}
	if wire.Username == "" || wire.Password == "" {
		return nil, fmt.Errorf("empty username/password")
	}

	// Prefer v2 shape (carries scheme + transport per URL). Fall back
	// to v1 turn_servers []string when v2 is absent — keeps the new
	// Go-side runner compatible with extensions still writing the old
	// JSON during a rolling deploy.
	var turnURLs []string
	var turnServers []wgturnclient.TurnServer
	if len(wire.TurnServersV2) > 0 {
		for _, s := range wire.TurnServersV2 {
			if s.Host == "" || s.Port == 0 {
				continue
			}
			scheme := strings.ToLower(strings.TrimSpace(s.Scheme))
			if scheme == "" {
				scheme = "turn"
			}
			transport := strings.ToLower(strings.TrimSpace(s.Transport))
			if transport == "" {
				if scheme == "turns" {
					transport = "tcp"
				} else {
					transport = "udp"
				}
			}
			if transport != "udp" && transport != "tcp" {
				transport = "udp"
			}
			if scheme == "turns" {
				// This client implements TURNS as TLS over TCP. VK may omit
				// transport or send mixed-case/legacy values; never let a
				// turns: URL fall into the UDP dial path.
				transport = "tcp"
			}
			turnServers = append(turnServers, wgturnclient.TurnServer{
				Host:      s.Host,
				Port:      s.Port,
				Scheme:    scheme,
				Transport: transport,
			})
			turnURLs = append(turnURLs, fmt.Sprintf("%s:%d", s.Host, s.Port))
		}
	}
	if len(turnURLs) == 0 {
		// v1 fallback path.
		turnURLs = wire.TurnServers
	}
	if len(turnURLs) == 0 {
		return nil, fmt.Errorf("empty turn_servers")
	}

	lifetime := wire.LifetimeSec
	if lifetime <= 0 {
		lifetime = 3600
	}
	return &wgturnclient.Credentials{
		User:        wire.Username,
		Pass:        wire.Password,
		TurnURLs:    turnURLs,
		TurnServers: turnServers,
		Lifetime:    lifetime,
	}, nil
}

// shouldUseUDP picks the wire transport for the runner. Preference
// order: UDP > TCP. When the v2 shape is present we look for any
// server advertising UDP; if there is one, we run UDP and let the
// session loop pick that server first (sessions iterate
// sessionID%len(TurnURLs), so VK's UDP relay sits at the same index
// in both lists). When v2 is absent we keep the historical
// hard-coded UDP behaviour.
func shouldUseUDP(creds *wgturnclient.Credentials) bool {
	if creds == nil || len(creds.TurnServers) == 0 {
		return true
	}
	for _, s := range creds.TurnServers {
		if strings.ToLower(strings.TrimSpace(s.Scheme)) == "turns" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(s.Transport)) == "udp" {
			return true
		}
	}
	return false
}

func resetVKTurnAtomicsLocked() {
	vkturnWGConfig.Store(nil)
	vkturnStats.Store(nil)
	vkturnErr.Store(nil)
	vkturnNet.Store(nil)
	vkturnRunning.Store(false)
}

func storeVKTurnStats(active int, running bool) {
	snapshot := fmt.Sprintf(`{"active":%d,"running":%t}`, active, running)
	vkturnStats.Store(&snapshot)
}
