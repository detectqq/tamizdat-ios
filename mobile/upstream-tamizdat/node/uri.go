package node

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Profile is the canonical tamizdat:// URI representation.
type Profile struct {
	MasterShortID       [8]byte
	PrimarySNI          string
	Pubkey              []byte
	Host                string
	Port                int
	CoverTrafficTargets []string
	Label               string
}

// ParseURI parses the canonical F-shape samizdat URI:
// tamizdat://<master_hex>@<host>:<port>?pbk=<hex>&sni=<hostname>[&cpool=<csv>]#<label>
func ParseURI(raw string) (*Profile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URI")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse URI: %w", err)
	}
	if u.Scheme != "tamizdat" {
		return nil, fmt.Errorf("bad scheme %q", u.Scheme)
	}
	masterHex := ""
	if u.User != nil {
		masterHex = u.User.Username()
	}
	if masterHex == "" {
		return nil, fmt.Errorf("missing master shortID")
	}
	masterBytes, err := decodeFixedHex(masterHex, 8, "master shortID")
	if err != nil {
		return nil, err
	}
	var master [8]byte
	copy(master[:], masterBytes)

	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("server address must be host:port: %w", err)
	}
	if host == "" || portStr == "" {
		return nil, fmt.Errorf("server address must include host and port")
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, fmt.Errorf("server port: %w", err)
	}

	q := u.Query()
	pub, err := decodeFixedHex(q.Get("pbk"), 32, "pbk")
	if err != nil {
		return nil, err
	}
	sni := strings.TrimSpace(q.Get("sni"))
	if sni == "" {
		return nil, fmt.Errorf("missing sni")
	}

	cpool, err := parseCpoolRaw(u.RawQuery)
	if err != nil {
		return nil, err
	}

	return &Profile{
		MasterShortID:       master,
		PrimarySNI:          sni,
		Pubkey:              pub,
		Host:                host,
		Port:                port,
		CoverTrafficTargets: cpool,
		Label:               u.Fragment,
	}, nil
}

func decodeFixedHex(s string, wantLen int, name string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("missing %s", name)
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

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("out of range %d", p)
	}
	return p, nil
}

func parseCpoolRaw(rawQuery string) ([]string, error) {
	var rawValues []string
	if rawQuery == "" {
		return nil, nil
	}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		keyRaw, valueRaw, hasValue := strings.Cut(part, "=")
		key, err := url.QueryUnescape(keyRaw)
		if err != nil {
			return nil, fmt.Errorf("query key: %w", err)
		}
		if key != "cpool" {
			continue
		}
		if !hasValue {
			valueRaw = ""
		}
		rawValues = append(rawValues, valueRaw)
	}
	if len(rawValues) == 0 {
		return nil, nil
	}
	if len(rawValues) > 1 {
		return nil, fmt.Errorf("cpool: duplicate parameter")
	}
	decoded, err := url.QueryUnescape(rawValues[0])
	if err != nil {
		return nil, fmt.Errorf("cpool: decode: %w", err)
	}
	if decoded == "" {
		return nil, fmt.Errorf("cpool: empty value")
	}
	for i := 0; i < len(decoded); i++ {
		if decoded[i] >= 128 {
			return nil, fmt.Errorf("cpool: non-ASCII byte")
		}
	}
	parts := strings.Split(decoded, ",")
	if len(parts) == 0 {
		return nil, fmt.Errorf("cpool: empty value")
	}
	if len(parts) > 32 {
		return nil, fmt.Errorf("cpool: too many entries")
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, fmt.Errorf("cpool: empty entry")
		}
		host, portStr, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, fmt.Errorf("cpool: %q is not host:port: %w", entry, err)
		}
		if host == "" {
			return nil, fmt.Errorf("cpool: empty host")
		}
		if _, err := parsePort(portStr); err != nil {
			return nil, fmt.Errorf("cpool: port: %w", err)
		}
		out = append(out, entry)
	}
	return out, nil
}
