package samizdat

import (
	"strings"
	"testing"
	"time"
)

const validBlob = "samizdat://llm2.detectqq.dpdns.org:8443/?sni=ok.ru" +
	"&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363" +
	"&shortid=d1b122782219759f&fp=chrome"

func TestParseConfig_OK(t *testing.T) {
	cfg, err := parseConfig(validBlob)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.ServerHost != "llm2.detectqq.dpdns.org" {
		t.Errorf("host = %q", cfg.ServerHost)
	}
	if cfg.ServerPort != 8443 {
		t.Errorf("port = %d", cfg.ServerPort)
	}
	if cfg.SNI != "ok.ru" {
		t.Errorf("sni = %q", cfg.SNI)
	}
	if cfg.Fingerprint != "chrome" {
		t.Errorf("fp = %q", cfg.Fingerprint)
	}
}

func TestParseConfig_Errors(t *testing.T) {
	cases := []struct {
		blob, contains string
	}{
		{"https://example.com", "samizdat://"},
		{"samizdat://:8443/?sni=x&pubkey=" + strings.Repeat("a", 64) +
			"&shortid=" + strings.Repeat("b", 16), "missing host"},
		{"samizdat://h:0/?sni=x&pubkey=" + strings.Repeat("a", 64) +
			"&shortid=" + strings.Repeat("b", 16), "invalid port"},
		{"samizdat://h:1/?pubkey=" + strings.Repeat("a", 64) +
			"&shortid=" + strings.Repeat("b", 16), "missing ?sni="},
		{"samizdat://h:1/?sni=x&pubkey=zz&shortid=" + strings.Repeat("b", 16), "pubkey"},
		{"samizdat://h:1/?sni=x&pubkey=" + strings.Repeat("a", 64) + "&shortid=zz", "shortid"},
		{"samizdat://h:1/?sni=x&pubkey=" + strings.Repeat("a", 64) +
			"&shortid=" + strings.Repeat("b", 16) + "&fp=opera", "fp must"},
	}
	for _, tc := range cases {
		_, err := parseConfig(tc.blob)
		if err == nil {
			t.Errorf("expected error for %q", tc.blob)
			continue
		}
		if !strings.Contains(err.Error(), tc.contains) {
			t.Errorf("err for %q = %q, want contains %q", tc.blob, err, tc.contains)
		}
	}
}

func TestConnectStubLifecycle(t *testing.T) {
	// reset
	rt = &runtimeState{state: StateDisconnected, logsMax: 1000}

	if got := Status(); got != StateDisconnected {
		t.Fatalf("initial status = %q", got)
	}
	if err := Connect(validBlob); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if got := Status(); got != StateConnecting && got != StateConnected {
		t.Errorf("immediately after Connect, status = %q", got)
	}
	// Stub takes ~900ms.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if Status() == StateConnected {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := Status(); got != StateConnected {
		t.Fatalf("after wait, status = %q", got)
	}
	if got := SocksAddr(); got != "127.0.0.1:1080" {
		t.Errorf("SocksAddr = %q", got)
	}
	Disconnect()
	if got := Status(); got != StateDisconnected {
		t.Errorf("after Disconnect, status = %q", got)
	}
}

func TestParseConfigError(t *testing.T) {
	if got := ParseConfigError(validBlob); got != "" {
		t.Errorf("valid blob got error %q", got)
	}
	if got := ParseConfigError("nope"); got == "" {
		t.Error("invalid blob: expected non-empty error")
	}
}
