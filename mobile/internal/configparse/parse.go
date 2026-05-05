// Package configparse is the single source of truth for samizdat://
// and tamizdat:// URI parsing across mobile/. The samizdat (gomobile-
// facing) and netstack packages both call Parse so any drift between
// them is impossible.
//
// History: prior to Phase 1 (gvisor migration), parseConfig lived
// privately in mobile/samizdat/samizdat.go and an independent copy
// in mobile/socksstub/socksstub.go drifted by ~10% — IPA-M shipped a
// bug where the UI accepted a URI shape the runtime then rejected.
// Single owner here prevents the regression.
package configparse

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Config is the parsed view a runtime caller (netstack bridge,
// socksstub, samizdat package) needs to construct a tamizdat client.
// Field types are deliberately runtime-friendly (PubkeyBytes is the
// 32-byte slice tamizdat.ClientConfig.PublicKey wants;
// ShortIDArray is the [8]byte tamizdat expects in ShortID/MasterShortID).
type Config struct {
	ServerHost       string
	ServerPort       int
	SNI              string   // primary SNI (first of pool)
	SNIPool          []string // optional rotation pool (>=2 entries when set)
	PubkeyHex        string
	PubkeyBytes      []byte    // 32 bytes
	ShortIDHex       string
	ShortIDArray     [8]byte
	Fingerprint      string
	TCPFragmentation bool
}

// Parse accepts the user-pasted URI blob in either legacy
// (`samizdat://h:p/?shortid=…&pubkey=…`) or xray-style
// (`samizdat://shortid@h:p?pbk=…`) form and validates every field
// the iOS runtime relies on. ErrMessage strings here surface in the
// UI's "paste failed" toast; keep them user-readable.
func Parse(blob string) (*Config, error) {
	u, err := url.Parse(blob)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}
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
	if connectHost := q.Get("connect_host"); connectHost != "" {
		host = connectHost
	}
	if connectPort := q.Get("connect_port"); connectPort != "" {
		parsedPort, err := strconv.Atoi(connectPort)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			return nil, fmt.Errorf("invalid connect_port %q", connectPort)
		}
		port = parsedPort
	}

	// SNI: snipool=a,b,c (xray-style rotation) takes precedence over
	// single sni= when set. We surface BOTH the primary (first non-empty)
	// AND the full pool so callers wanting rotation can use it.
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
		return nil, errors.New("missing ?sni= (or snipool=)")
	}

	// Pubkey: pbk= (xray) | pubkey= (legacy) | public-key-hex= (older)
	pub := q.Get("pbk")
	if pub == "" {
		pub = q.Get("pubkey")
	}
	if pub == "" {
		pub = q.Get("public-key-hex")
	}
	if len(pub) != 64 || !isHex(pub) {
		return nil, errors.New("pubkey must be 64 hex chars (use pbk= or pubkey=)")
	}
	pubBytes, err := hex.DecodeString(pub)
	if err != nil { // can only fail on case mix corruption; isHex already covers content
		return nil, fmt.Errorf("pubkey hex decode: %w", err)
	}

	// ShortID: userinfo before @ (xray) takes precedence; falls back
	// to legacy shortid= query. Both accept comma-separated lists for
	// backward compat — only the first entry is used (HKDF derives
	// the per-stream pool from the master client-side).
	sid := ""
	if u.User != nil {
		userinfo := u.User.Username()
		for _, s := range strings.Split(userinfo, ",") {
			if t := strings.TrimSpace(s); t != "" {
				sid = t
				break
			}
		}
	}
	if sid == "" {
		sid = q.Get("shortid")
		if sid != "" && strings.Contains(sid, ",") {
			for _, s := range strings.Split(sid, ",") {
				if t := strings.TrimSpace(s); t != "" {
					sid = t
					break
				}
			}
		}
	}
	if len(sid) != 16 || !isHex(sid) {
		return nil, errors.New("shortid must be 16 hex chars (userinfo or shortid=)")
	}
	sidBytes, err := hex.DecodeString(sid)
	if err != nil {
		return nil, fmt.Errorf("shortid hex decode: %w", err)
	}
	var sidArr [8]byte
	copy(sidArr[:], sidBytes)

	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	switch fp {
	case "chrome", "firefox", "safari", "edge", "ios",
		"mix", "auto", "rotate":
		// acceptable
	default:
		return nil, fmt.Errorf("fp must be chrome/firefox/safari/edge/ios/mix/auto/rotate (got %q)", fp)
	}

	tcpFrag := true
	if raw := q.Get("tcpfrag"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("tcpfrag must be true/false (got %q)", raw)
		}
		tcpFrag = parsed
	}

	return &Config{
		ServerHost:       host,
		ServerPort:       port,
		SNI:              sni,
		SNIPool:          sniPool,
		PubkeyHex:        pub,
		PubkeyBytes:      pubBytes,
		ShortIDHex:       sid,
		ShortIDArray:     sidArr,
		Fingerprint:      fp,
		TCPFragmentation: tcpFrag,
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
