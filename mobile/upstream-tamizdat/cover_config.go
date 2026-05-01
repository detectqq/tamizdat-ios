package tamizdat

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	configAuthority           = "tamizdat-config.invalid:443"
	SamizdatProtocolConfig    = "config/1"
	MaxCoverConfigBundleBytes = 4096
)

// CoverConfigBundle is the server-pushed config bundle JSON v1.
type CoverConfigBundle struct {
	Version         int        `json:"version"`
	EpochKey        string     `json:"epoch_key,omitempty"`
	ShortIDPoolSize int        `json:"shortid_pool_size,omitempty"`
	SNIPool         []SNIEntry `json:"sni_pool,omitempty"`
	CoverTargets    []string   `json:"cover_targets,omitempty"`
	CoverGapMinMS   int        `json:"cover_gap_min_ms,omitempty"`
	CoverGapMaxMS   int        `json:"cover_gap_max_ms,omitempty"`
}

func LoadCoverConfig(path string) (*CoverConfigBundle, error) {
	return loadCoverConfig(path, nil, false)
}

func LoadCoverConfigWithMasquerade(path string, masqPool map[string]string) (*CoverConfigBundle, error) {
	return loadCoverConfig(path, masqPool, true)
}

func loadCoverConfig(path string, masqPool map[string]string, checkMasq bool) (*CoverConfigBundle, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cover config: %w", err)
	}
	if len(buf) > MaxCoverConfigBundleBytes {
		return nil, fmt.Errorf("cover config too large: %d > %d bytes", len(buf), MaxCoverConfigBundleBytes)
	}
	var bundle CoverConfigBundle
	if err := json.Unmarshal(buf, &bundle); err != nil {
		return nil, fmt.Errorf("parse cover config: %w", err)
	}
	if err := bundle.Validate(masqPool, checkMasq); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func (b *CoverConfigBundle) Validate(masqPool map[string]string, checkMasq bool) error {
	if b == nil {
		return fmt.Errorf("cover config: nil bundle")
	}
	if b.Version != 1 {
		return fmt.Errorf("cover config: version must be 1, got %d", b.Version)
	}
	if b.ShortIDPoolSize < 0 || b.ShortIDPoolSize > 1000 {
		return fmt.Errorf("cover config: shortid_pool_size %d out of range [0,1000]", b.ShortIDPoolSize)
	}
	if b.EpochKey != "" {
		if len(b.EpochKey) > 64 {
			return fmt.Errorf("cover config: epoch_key too long: %d > 64", len(b.EpochKey))
		}
		if !isASCII(b.EpochKey) || !utf8.ValidString(b.EpochKey) {
			return fmt.Errorf("cover config: epoch_key must be ASCII")
		}
	}
	if checkMasq {
		for _, e := range b.SNIPool {
			if strings.TrimSpace(e.SNI) == "" {
				return fmt.Errorf("cover config: sni_pool contains empty sni")
			}
			if _, ok := masqPool[e.SNI]; !ok {
				return fmt.Errorf("cover config: sni_pool entry %q is not present in masquerade pool", e.SNI)
			}
		}
	}
	for _, target := range b.CoverTargets {
		if err := validateHostPort(target); err != nil {
			return fmt.Errorf("cover config: cover_target %q: %w", target, err)
		}
	}
	if b.CoverGapMinMS != 0 || b.CoverGapMaxMS != 0 {
		if b.CoverGapMinMS < 1 || b.CoverGapMinMS > 600000 {
			return fmt.Errorf("cover config: cover_gap_min_ms %d out of range [1,600000]", b.CoverGapMinMS)
		}
		if b.CoverGapMaxMS < 1 || b.CoverGapMaxMS > 600000 {
			return fmt.Errorf("cover config: cover_gap_max_ms %d out of range [1,600000]", b.CoverGapMaxMS)
		}
		if b.CoverGapMinMS > b.CoverGapMaxMS {
			return fmt.Errorf("cover config: cover_gap_min_ms greater than cover_gap_max_ms")
		}
	}
	return nil
}

func (b *CoverConfigBundle) MarshalForWire() ([]byte, error) {
	if b == nil {
		b = &CoverConfigBundle{Version: 1}
	}
	buf, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal cover config: %w", err)
	}
	if len(buf) > MaxCoverConfigBundleBytes {
		return nil, fmt.Errorf("cover config too large after marshal: %d > %d bytes", len(buf), MaxCoverConfigBundleBytes)
	}
	return buf, nil
}

func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("empty host")
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d out of range [1,65535]", p)
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			return false
		}
	}
	return true
}
