// Package configurl parses tamizdat:// client configuration URLs.
package configurl

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Config is the transport-neutral representation of a tamizdat:// URL.
type Config struct {
	ServerAddr    string
	ServerName    string   // legacy single SNI; first pool entry
	ServerNames   []string // pool of SNIs from comma-separated sni query param
	PublicKey     []byte
	MasterShortID [8]byte
	Fingerprint   string
}

// Parse converts a tamizdat:// URL into a validated Config.
//
// Accepted forms (any of these works):
//
//	tamizdat://<host>:<port>/?sni=<hostname>&pubkey=<64hex>&shortid=<16hex>&fp=chrome   (canonical)
//	tamizdat://<shortid>@<host>:<port>?sni=<hostname>&pbk=<64hex>&fp=chrome             (legacy samizdat form)
//	samizdat://<shortid>@<host>:<port>?sni=<hostname>&pbk=<64hex>&fp=chrome             (samizdat scheme alias)
//
// Aliases: "pbk" == "pubkey", "sid" == "shortid", userinfo == "shortid".
func Parse(raw string) (Config, error) {
	var cfg Config

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg, fmt.Errorf("empty config URL")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return cfg, fmt.Errorf("parse config URL: %w", err)
	}
	if u.Scheme != "tamizdat" && u.Scheme != "samizdat" {
		return cfg, fmt.Errorf("unsupported config URL scheme %q (want tamizdat:// or samizdat://)", u.Scheme)
	}
	if u.Host == "" {
		return cfg, fmt.Errorf("config URL must include server host:port")
	}
	if u.Path != "" && u.Path != "/" {
		return cfg, fmt.Errorf("config URL path must be empty or '/', got %q", u.Path)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return cfg, fmt.Errorf("server address must be host:port: %w", err)
	}
	if host == "" || port == "" {
		return cfg, fmt.Errorf("server address must include non-empty host and port")
	}
	cfg.ServerAddr = net.JoinHostPort(host, port)

	q := u.Query()
	sniRaw := strings.TrimSpace(q.Get("sni"))
	if sniRaw == "" {
		return cfg, fmt.Errorf("missing required sni query parameter")
	}
	for _, p := range strings.Split(sniRaw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			cfg.ServerNames = append(cfg.ServerNames, p)
		}
	}
	if len(cfg.ServerNames) == 0 {
		return cfg, fmt.Errorf("sni: at least one entry required")
	}
	cfg.ServerName = cfg.ServerNames[0] // legacy field

	// Accept "pubkey" (canonical tamizdat) or "pbk" (legacy samizdat) — both mean the same.
	pubRaw := q.Get("pubkey")
	if strings.TrimSpace(pubRaw) == "" {
		pubRaw = q.Get("pbk")
	}
	pub, err := decodeFixedHex(pubRaw, 32, "pubkey/pbk")
	if err != nil {
		return cfg, err
	}
	cfg.PublicKey = pub

	// Accept shortid from "?shortid=" (canonical), "?sid=" (alias),
	// or from URL userinfo (legacy samizdat form: tamizdat://SHORTID@host:port?...).
	shortIDStr := strings.TrimSpace(q.Get("shortid"))
	if shortIDStr == "" {
		shortIDStr = strings.TrimSpace(q.Get("sid"))
	}
	if shortIDStr == "" && u.User != nil {
		shortIDStr = strings.TrimSpace(u.User.Username())
	}
	if shortIDStr == "" {
		return cfg, fmt.Errorf("missing required shortid (provide as ?shortid=, ?sid= or in URL userinfo)")
	}
	b, err := decodeFixedHex(shortIDStr, 8, "shortid")
	if err != nil {
		return cfg, err
	}
	copy(cfg.MasterShortID[:], b)

	cfg.Fingerprint = strings.TrimSpace(q.Get("fp"))
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "mix"
	}

	return cfg, nil
}

func decodeFixedHex(s string, wantLen int, name string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("missing required %s query parameter", name)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", name, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("%s must decode to %d bytes, got %d", name, wantLen, len(b))
	}
	return b, nil
}
