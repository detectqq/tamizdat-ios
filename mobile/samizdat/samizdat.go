// Package samizdat is the gomobile-friendly shim around the samizdat proxy
// client. It exposes a small, simple API designed to cross the Go↔Swift
// boundary cleanly. The Swift import name is SamizdatClient and exported
// functions are prefixed Samizdat… (e.g. SamizdatConnect, SamizdatStatus).
//
// Iteration 1 (current): the API is fully wired and parses real samizdat://
// config blobs, but Connect() simulates the network connection (no real
// tunnel yet). The UI, signing, build, and sideload pipeline can be
// validated end-to-end without depending on the real samizdat.NewClient
// integration. Iteration 2 will swap the simulation for a real
// samizdat.Client and a local SOCKS5 listener.
package samizdat

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// State strings returned by Status(). Stable across iterations.
const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateError        = "error"
)

// Config is the parsed form of a samizdat:// URL.
//
// Note: gomobile bind tolerates structs of basic types; we do not return this
// across the boundary, only use it internally. Swift sees only the strings
// from Status()/LastError()/etc.
type config struct {
	ServerHost  string
	ServerPort  int
	SNI         string
	PubkeyHex   string // 64 hex chars
	ShortIDHex  string // 16 hex chars
	Fingerprint string // chrome / firefox / safari
}

type runtimeState struct {
	mu        sync.Mutex
	state     string
	lastErr   string
	cfg       *config
	logs      []string
	logsMax   int
	cancelCh  chan struct{}
	socksAddr string
}

var rt = &runtimeState{
	state:   StateDisconnected,
	logsMax: 1000,
}

// Connect parses configBlob (a samizdat:// URL) and starts the (simulated)
// connection. Returns immediately; UI should poll Status() / LastError() /
// Logs() to render state.
//
// Returns an error only if the config blob is malformed. Network errors
// surface via Status()=="error" + LastError().
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
	rt.state = StateConnecting
	rt.lastErr = ""
	rt.cfg = cfg
	rt.cancelCh = make(chan struct{})
	cancelCh := rt.cancelCh
	rt.mu.Unlock()

	rt.appendLog(fmt.Sprintf("info: connecting to %s:%d (SNI=%s, fp=%s)",
		cfg.ServerHost, cfg.ServerPort, cfg.SNI, cfg.Fingerprint))
	rt.appendLog(fmt.Sprintf("info: short_id=%s pubkey=%s…", cfg.ShortIDHex, cfg.PubkeyHex[:16]))

	// Simulate handshake. Iteration 2 replaces this with samizdat.NewClient +
	// local SOCKS5 listener.
	go func() {
		select {
		case <-time.After(900 * time.Millisecond):
		case <-cancelCh:
			rt.appendLog("info: connect cancelled")
			rt.setState(StateDisconnected)
			return
		}
		rt.mu.Lock()
		rt.state = StateConnected
		rt.socksAddr = "127.0.0.1:1080" // listener address (stub)
		rt.mu.Unlock()
		rt.appendLog("info: handshake ok (stub)")
		rt.appendLog("info: SOCKS5 listening on 127.0.0.1:1080 (stub — no real tunnel yet)")
	}()

	return nil
}

// Disconnect tears down the connection. Idempotent.
func Disconnect() {
	rt.mu.Lock()
	if rt.cancelCh != nil {
		close(rt.cancelCh)
		rt.cancelCh = nil
	}
	rt.state = StateDisconnected
	rt.socksAddr = ""
	rt.mu.Unlock()
	rt.appendLog("info: disconnected")
}

// Status returns the current state string.
func Status() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.state
}

// LastError returns the last error message (empty if none).
func LastError() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.lastErr
}

// SocksAddr returns the local SOCKS5 listen address while connected,
// otherwise an empty string.
func SocksAddr() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.socksAddr
}

// Logs returns the last n log lines joined by "\n". If n<=0 returns all.
func Logs(n int) string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if n <= 0 || n > len(rt.logs) {
		n = len(rt.logs)
	}
	if n == 0 {
		return ""
	}
	start := len(rt.logs) - n
	out := ""
	for i, l := range rt.logs[start:] {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}

// ClearLogs empties the in-memory log buffer.
func ClearLogs() {
	rt.mu.Lock()
	rt.logs = rt.logs[:0]
	rt.mu.Unlock()
}

// ParseConfigError validates a samizdat:// blob without connecting. Returns
// empty string on success, or a human-readable error message.
//
// Useful for the "Save" button on the Config paste modal.
func ParseConfigError(configBlob string) string {
	if _, err := parseConfig(configBlob); err != nil {
		return err.Error()
	}
	return ""
}

// Version returns the shim version. Bump on protocol-affecting changes.
func Version() string {
	return "0.1.0-stub"
}

// ── internal helpers ──────────────────────────────────────────────────────────

func (r *runtimeState) setState(s string) {
	r.mu.Lock()
	r.state = s
	r.mu.Unlock()
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
		// drop oldest in chunks to avoid copying every line
		drop := len(r.logs) - r.logsMax
		r.logs = append(r.logs[:0], r.logs[drop:]...)
	}
	r.mu.Unlock()
}

// parseConfig accepts a samizdat:// URL and returns a populated config or
// a descriptive error.
//
// Format:
//
//	samizdat://<host>:<port>/?sni=<hostname>&pubkey=<64hex>&shortid=<16hex>&fp=chrome
func parseConfig(blob string) (*config, error) {
	u, err := url.Parse(blob)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}
	if u.Scheme != "samizdat" {
		return nil, fmt.Errorf("scheme must be samizdat:// (got %q)", u.Scheme)
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

	sni := q.Get("sni")
	if sni == "" {
		return nil, errors.New("missing ?sni=")
	}
	pub := q.Get("pubkey")
	if len(pub) != 64 || !isHex(pub) {
		return nil, errors.New("pubkey must be 64 hex chars")
	}
	sid := q.Get("shortid")
	if len(sid) != 16 || !isHex(sid) {
		return nil, errors.New("shortid must be 16 hex chars")
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	switch fp {
	case "chrome", "firefox", "safari":
	default:
		return nil, fmt.Errorf("fp must be chrome/firefox/safari (got %q)", fp)
	}
	return &config{
		ServerHost:  host,
		ServerPort:  port,
		SNI:         sni,
		PubkeyHex:   pub,
		ShortIDHex:  sid,
		Fingerprint: fp,
	}, nil
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
