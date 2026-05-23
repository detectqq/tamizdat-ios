package socksstub

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/detectqq/tamizdat/wgturnclient"
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
	vkturnRunner   *wgturnclient.Runner
	vkturnCancel   context.CancelFunc
	vkturnWGConfig atomic.Pointer[string]
	vkturnStats    atomic.Pointer[string]
	vkturnErr      atomic.Pointer[string]
	vkturnRunning  atomic.Bool
	vkturnMu       sync.Mutex
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

	runner, err := wgturnclient.New(wgturnclient.Config{
		Listen:         fmt.Sprintf("127.0.0.1:%d", listenPort),
		PeerAddr:       peerAddr,
		Workers:        12,
		UseUDP:         true,
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
		vkturnRunning.Store(false)
		storeVKTurnStats(0, false)
		vkturnRunner = nil
		vkturnCancel = nil
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if p := vkturnWGConfig.Load(); p != nil {
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

// StopVKTurnUpstream stops the in-flight runner. Idempotent.
func StopVKTurnUpstream() {
	vkturnMu.Lock()
	defer vkturnMu.Unlock()

	if !vkturnRunning.Load() {
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

func parseVKTurnCredsJSON(credsJSON string) (*wgturnclient.Credentials, error) {
	var wire struct {
		Username    string   `json:"username"`
		Password    string   `json:"password"`
		TurnServers []string `json:"turn_servers"`
		LifetimeSec int      `json:"lifetime_sec"`
	}
	if err := json.Unmarshal([]byte(credsJSON), &wire); err != nil {
		return nil, err
	}
	if wire.Username == "" || wire.Password == "" || len(wire.TurnServers) == 0 {
		return nil, fmt.Errorf("empty username/password/turn_servers")
	}
	lifetime := wire.LifetimeSec
	if lifetime <= 0 {
		lifetime = 3600
	}
	return &wgturnclient.Credentials{
		User:     wire.Username,
		Pass:     wire.Password,
		TurnURLs: wire.TurnServers,
		Lifetime: lifetime,
	}, nil
}

func resetVKTurnAtomicsLocked() {
	vkturnWGConfig.Store(nil)
	vkturnStats.Store(nil)
	vkturnErr.Store(nil)
	vkturnRunning.Store(false)
}

func storeVKTurnStats(active int, running bool) {
	snapshot := fmt.Sprintf(`{"active":%d,"running":%t}`, active, running)
	vkturnStats.Store(&snapshot)
}
