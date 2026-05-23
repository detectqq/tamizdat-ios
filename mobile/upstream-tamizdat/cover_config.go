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

	// Phase C iOS-notify (Stage 3, 2026-05-10): one-shot per-user message
	// piggy-backed on the bundle. When set, the client SHOULD display it
	// to the user once and dismiss. Server injects per-user when the
	// caller's users.notification_pending=1 (quota_exhausted / expired /
	// admin_message / admin_broadcast) and clears the pending flag after
	// a successful body write. Empty in cached/global bundles.
	Notification *NotificationEntry `json:"notification,omitempty"`

	// TURNCreds carries VK TURN relay credentials obtained by the
	// server's turncreds.Manager. Clients that support TURN-based
	// transport use these to establish relay connections through VK
	// infrastructure. Older clients silently ignore the field.
	TURNCreds *TURNCredsEntry `json:"turn_creds,omitempty"`
}

// TURNCredsEntry carries TURN relay credentials for client-side TURN
// transport. Lifetime is in seconds from the time the credentials
// were issued by VK; clients should re-fetch the bundle before
// lifetime expires to obtain fresh credentials.
type TURNCredsEntry struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	URLs     []string `json:"urls"`
	Lifetime int      `json:"lifetime"`
}

// NotificationEntry is a one-shot user-facing message delivered via the
// bundle (Phase C iOS-notify, Stage 3, 2026-05-10).
//
//   - Code:   machine-readable cause, e.g. "quota_exhausted", "expired",
//             "admin_broadcast". Stable across versions.
//   - Title:  short human-readable title for an OS-level banner.
//   - Body:   longer free-form text, may be empty.
//   - Locale: BCP-47 hint ("ru", "en", …) for the title/body the server
//             picked. Client may ignore and pick by Code.
type NotificationEntry struct {
	Code   string `json:"code"`
	Title  string `json:"title,omitempty"`
	Body   string `json:"body,omitempty"`
	Locale string `json:"locale,omitempty"`
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
	if b.Notification != nil {
		if strings.TrimSpace(b.Notification.Code) == "" {
			return fmt.Errorf("cover config: notification.code must be non-empty")
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
