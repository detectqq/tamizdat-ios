package tamizdat

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCoverConfigTestFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadCoverConfigValid(t *testing.T) {
	path := writeCoverConfigTestFile(t, `{
		"version":1,
		"epoch_key":"ep-2026-05-01-rotated",
		"shortid_pool_size":100,
		"sni_pool":[{"sni":"yandex.ru","weight":100},{"sni":"vk.com","weight":90}],
		"cover_targets":["mc.yandex.ru:443","an.yandex.ru:443"],
		"cover_gap_min_ms":30000,
		"cover_gap_max_ms":90000
	}`)
	bundle, err := LoadCoverConfigWithMasquerade(path, map[string]string{"yandex.ru": "yandex.ru", "vk.com": "vk.com"})
	if err != nil {
		t.Fatalf("LoadCoverConfigWithMasquerade: %v", err)
	}
	if bundle.Version != 1 || bundle.EpochKey != "ep-2026-05-01-rotated" || bundle.ShortIDPoolSize != 100 {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}
	if len(bundle.SNIPool) != 2 || len(bundle.CoverTargets) != 2 {
		t.Fatalf("pool lengths: sni=%d cover=%d", len(bundle.SNIPool), len(bundle.CoverTargets))
	}
}

func TestLoadCoverConfigInvalid(t *testing.T) {
	tooLongEpoch := "ep-" + strings.Repeat("x", 65)
	cases := map[string]struct {
		body     string
		pathOnly string
		masq     map[string]string
	}{
		"empty file":                     {body: ""},
		"file-not-found":                 {pathOnly: filepath.Join(t.TempDir(), "missing.json")},
		"JSON-parse-error":               {body: `{"version":`},
		"version!=1":                     {body: `{"version":2}`},
		"missing-required-field":         {body: `{}`},
		"sni-not-in-masq-pool":           {body: `{"version":1,"sni_pool":[{"sni":"vk.com","weight":1}]}`, masq: map[string]string{"ok.ru": "ok.ru"}},
		"cover-target-bad-port":          {body: `{"version":1,"cover_targets":["mc.yandex.ru:70000"]}`},
		"cover-gap-min-greater-than-max": {body: `{"version":1,"cover_gap_min_ms":90000,"cover_gap_max_ms":30000}`},
		"shortid-pool-size-out-of-range": {body: `{"version":1,"shortid_pool_size":1001}`},
		"epoch-key-non-ASCII":            {body: `{"version":1,"epoch_key":"ключ"}`},
		"epoch-key-too-long":             {body: `{"version":1,"epoch_key":"` + tooLongEpoch + `"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := tc.pathOnly
			if path == "" {
				path = writeCoverConfigTestFile(t, tc.body)
			}
			if tc.masq == nil {
				tc.masq = map[string]string{"vk.com": "vk.com", "ok.ru": "ok.ru"}
			}
			if _, err := LoadCoverConfigWithMasquerade(path, tc.masq); err == nil {
				t.Fatalf("LoadCoverConfigWithMasquerade succeeded for %s", name)
			}
		})
	}
}

func TestBundleSizeCapServerSide(t *testing.T) {
	path := writeCoverConfigTestFile(t, strings.Repeat(" ", MaxCoverConfigBundleBytes+1))
	if _, err := LoadCoverConfig(path); err == nil {
		t.Fatal("oversized bundle accepted")
	}
}

func TestBundleVersionUnknown(t *testing.T) {
	path := writeCoverConfigTestFile(t, `{"version":99}`)
	if _, err := LoadCoverConfig(path); err == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestServerCoverConfigInitializesDerivedPool(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	path := writeCoverConfigTestFile(t, `{"version":1,"epoch_key":"ep-current","shortid_pool_size":4}`)
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	server, err := NewServer(ServerConfig{
		PrivateKey:      priv,
		MasterShortID:   master,
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		CoverConfigPath: path,
		Handler:         func(ctx context.Context, conn net.Conn, destination string) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	derived := DeriveShortIDPool(master, "ep-current", 4)
	if !server.shortIDPool.Accept(derived[0]) {
		t.Fatal("server shortID pool did not accept configured epoch")
	}
	if string(server.coverConfigJSON) == "" || !strings.Contains(string(server.coverConfigJSON), "epoch_key") {
		t.Fatalf("coverConfigJSON not cached: %q", string(server.coverConfigJSON))
	}
}

func TestCoverConfigJSONRoundTrip(t *testing.T) {
	bundle := CoverConfigBundle{Version: 1, EpochKey: "ep", ShortIDPoolSize: 1}
	buf, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf), "epoch_key") || strings.Contains(string(buf), "shortid_pool_extra") {
		t.Fatalf("unexpected JSON shape: %s", buf)
	}
}
