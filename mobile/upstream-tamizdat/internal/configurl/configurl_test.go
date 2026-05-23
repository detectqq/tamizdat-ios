package configurl

import "testing"

const testURL = "tamizdat://llm2.detectqq.dpdns.org:8443/?sni=ok.ru&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f&fp=chrome"

func TestParse(t *testing.T) {
	cfg, err := Parse(testURL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ServerAddr != "llm2.detectqq.dpdns.org:8443" {
		t.Fatalf("ServerAddr = %q", cfg.ServerAddr)
	}
	if cfg.ServerName != "ok.ru" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if len(cfg.PublicKey) != 32 {
		t.Fatalf("PublicKey len = %d", len(cfg.PublicKey))
	}
	if cfg.MasterShortID != [8]byte{0xd1, 0xb1, 0x22, 0x78, 0x22, 0x19, 0x75, 0x9f} {
		t.Fatalf("MasterShortID = %x", cfg.MasterShortID)
	}
	if cfg.Fingerprint != "chrome" {
		t.Fatalf("Fingerprint = %q", cfg.Fingerprint)
	}
}

func TestParseDefaultsFingerprint(t *testing.T) {
	cfg, err := Parse("tamizdat://example.com:443/?sni=ok.ru&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Fingerprint != "mix" {
		t.Fatalf("Fingerprint = %q", cfg.Fingerprint)
	}
}

func TestParseRejectsMissingPort(t *testing.T) {
	if _, err := Parse("tamizdat://example.com/?sni=ok.ru&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f"); err == nil {
		t.Fatal("Parse succeeded without host:port")
	}
}
