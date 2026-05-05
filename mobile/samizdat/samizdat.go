// Package samizdat exposes a gomobile-friendly API for the iOS app and
// PacketTunnelProvider extension.
//
// Phase C migration (Path 4) status:
//   - The full-device VPN data path has moved to package
//     github.com/anarki/samizdat-ios/mobile/netstack (sing-tun + sagernet/
//     gvisor). The PacketTunnelProvider calls NetstackStart(fd, blob) on
//     startup; this package no longer owns the gvisor stack or the packet
//     pump.
//   - What remains here is the Swift-facing utility surface: config-blob
//     validation (delegated to mobile/internal/configparse), the running
//     state machine that drives the SwiftUI status icon, and the App Group
//     log sink that survives extension death.
//   - All TunnelStart / TunnelInjectPacket / TunnelReadPacket / packetFlow
//     plumbing was deleted along with the old gvisor.dev/gvisor imports.
//     gomobile bind on this package now produces a much smaller xcframework
//     (no embedded netstack, no gvisor TCP buffers).
package samizdat

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/anarki/samizdat-ios/mobile/internal/configparse"
)

const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateError        = "error"
)

// config is an alias of configparse.Config so the package's existing
// callsites stay terse. Single owner of the parser is the internal
// configparse package; both samizdat and netstack call into it.
type config = configparse.Config

type runtimeState struct {
	mu        sync.Mutex
	state     string
	lastErr   string
	cfg       *config
	logs      []string
	logsMax   int
	socksAddr string
}

var rt = &runtimeState{
	state:   StateDisconnected,
	logsMax: 1000,
}

// Log file sink. The iOS extension calls SetLogSink at startTunnel with a
// path inside the App Group container. Every appendLog also writes there,
// so the main app can read live logs by tailing the file (no XPC, no
// sendProviderMessage poll loop) AND the file survives extension death,
// giving us the "last words" trail when iOS reaps the process.
var (
	logSinkMu sync.Mutex
	logSink   *os.File
)

// SetLogSink opens the given path in append mode (creating if necessary).
// Subsequent appendLog calls also write there. Pass an empty string to
// detach the current sink.
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Don't appendLog about the sink failure — that would be circular if
		// the sink is also where we'd send the warning.
		_ = err
		return
	}
	logSinkMu.Lock()
	if logSink != nil {
		logSink.Close()
	}
	logSink = f
	logSinkMu.Unlock()
}

// Connect validates the configBlob and updates the visible state machine.
// In Path 4 (sing-tun + sagernet/gvisor in package netstack) it does NOT
// own the data path — PacketTunnelProvider calls netstack.Start(fd, blob)
// for that. This is kept as a smoke / config-validation entry point so the
// main app's "Connect" button can confirm a config parses before iOS is
// asked to spin up the tunnel.
func Connect(configBlob string) error {
	cfg, err := parseConfig(configBlob)
	if err != nil {
		rt.setError("parse: " + err.Error())
		return err
	}

	rt.mu.Lock()
	if rt.state == StateConnecting || rt.state == StateConnected {
		rt.mu.Unlock()
		return errors.New("already connecting or connected; call Disconnect first")
	}
	rt.state = StateConnected
	rt.lastErr = ""
	rt.cfg = cfg
	rt.socksAddr = ""
	rt.mu.Unlock()

	rt.appendLog(fmt.Sprintf("info: config ok for %s:%d; VPN engine runs in PacketTunnelProvider", cfg.ServerHost, cfg.ServerPort))
	return nil
}

// Disconnect resets the visible state machine. The actual data-path
// teardown (closing tamizdat client, draining sing-tun) is done by
// netstack.Stop, which the PacketTunnelProvider's stopTunnel handler
// calls directly.
func Disconnect() {
	rt.mu.Lock()
	rt.state = StateDisconnected
	rt.socksAddr = ""
	rt.mu.Unlock()
	rt.appendLog("info: disconnected")
}

func Status() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.state
}

func LastError() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.lastErr
}

func SocksAddr() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.socksAddr
}

func Logs(n int) string {
	rt.mu.Lock()
	if n <= 0 || n > len(rt.logs) {
		n = len(rt.logs)
	}
	if n == 0 {
		rt.mu.Unlock()
		return ""
	}
	start := len(rt.logs) - n
	snapshot := make([]string, n)
	copy(snapshot, rt.logs[start:])
	rt.mu.Unlock()

	var b strings.Builder
	b.Grow(n * 80)
	for i, l := range snapshot {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(l)
	}
	return b.String()
}

func ClearLogs() {
	rt.mu.Lock()
	rt.logs = rt.logs[:0]
	rt.mu.Unlock()
}

func ParseConfigError(configBlob string) string {
	if _, err := parseConfig(configBlob); err != nil {
		return err.Error()
	}
	return ""
}

func Version() string {
	return "0.2.0-vpn"
}

func AddLog(line string) {
	rt.appendLog(line)
}

// parseConfig delegates to the shared parser in
// mobile/internal/configparse. Kept as a thin wrapper so existing
// callers in this file (Connect / ParseConfigError) read naturally
// and so the rt.cfg type is the configparse.Config alias.
func parseConfig(blob string) (*config, error) {
	return configparse.Parse(blob)
}

func (r *runtimeState) setError(msg string) {
	r.mu.Lock()
	r.state = StateError
	r.lastErr = msg
	r.mu.Unlock()
	r.appendLog("error: " + msg)
}

func (r *runtimeState) appendLog(line string) {
	stamp := time.Now().Format("15:04:05.000")
	full := stamp + " " + line
	r.mu.Lock()
	r.logs = append(r.logs, full)
	if len(r.logs) > r.logsMax {
		drop := len(r.logs) - r.logsMax
		r.logs = append(r.logs[:0], r.logs[drop:]...)
	}
	r.mu.Unlock()

	// Mirror to the App Group log file outside r.mu so disk I/O doesn't
	// stall log producers. Concurrent writes are serialized by logSinkMu;
	// kernel append on a regular file is atomic per-write up to PIPE_BUF
	// for our short lines.
	logSinkMu.Lock()
	sink := logSink
	logSinkMu.Unlock()
	if sink != nil {
		_, _ = sink.WriteString(full + "\n")
	}
}
