package socksstub

import (
	"testing"
	"time"
)

// TestPingProberFailCounting verifies the "2 consecutive misses → failed"
// rule that drives the UI's yellow shield. We poke recordMiss/recordSuccess
// directly to bypass the actual HTTP probe; this test does NOT need a
// live samizdat client.
func TestPingProberFailCounting(t *testing.T) {
	// Snapshot + restore the package-global proberState — other tests in
	// this package don't touch it but we want to be polite.
	orig := proberState
	proberState = &pingProberState{}
	proberState.lastMs.Store(-1)
	defer func() { proberState = orig }()

	// Fresh state: not failed, no successful sample.
	snap := PingProbeSnapshot()
	if snap.Failed {
		t.Fatalf("fresh state should not be failed")
	}
	if snap.OK {
		t.Fatalf("fresh state OK should be false")
	}
	if snap.LastMs != -1 {
		t.Fatalf("fresh state LastMs = %d, want -1", snap.LastMs)
	}

	// One success → ok=true, lastMs updated, not failed.
	recordSuccess(42 * time.Millisecond)
	snap = PingProbeSnapshot()
	if !snap.OK {
		t.Errorf("after recordSuccess OK should be true")
	}
	if snap.LastMs != 42 {
		t.Errorf("after recordSuccess LastMs = %d, want 42", snap.LastMs)
	}
	if snap.Failed {
		t.Errorf("after recordSuccess Failed should be false")
	}

	// One miss → ok=false but NOT failed (only one miss).
	recordMiss()
	snap = PingProbeSnapshot()
	if snap.OK {
		t.Errorf("after 1 miss OK should be false")
	}
	if snap.Failed {
		t.Errorf("after 1 miss Failed should still be false (threshold is 2)")
	}
	if snap.LastMs != 42 {
		t.Errorf("after 1 miss LastMs should retain last success = 42, got %d", snap.LastMs)
	}

	// Second miss → failed.
	recordMiss()
	snap = PingProbeSnapshot()
	if !snap.Failed {
		t.Errorf("after 2 misses Failed should be true")
	}

	// Third miss → still failed.
	recordMiss()
	snap = PingProbeSnapshot()
	if !snap.Failed {
		t.Errorf("after 3 misses Failed should remain true")
	}

	// Recovery: one success clears Failed.
	recordSuccess(17 * time.Millisecond)
	snap = PingProbeSnapshot()
	if snap.Failed {
		t.Errorf("after recovery Failed should be false")
	}
	if !snap.OK {
		t.Errorf("after recovery OK should be true")
	}
	if snap.LastMs != 17 {
		t.Errorf("after recovery LastMs = %d, want 17", snap.LastMs)
	}
}

// TestSetPingProbeURL_FallsBackOnInvalid verifies that invalid URLs do
// not corrupt the prober state — they fall back to the default.
func TestSetPingProbeURL_FallsBackOnInvalid(t *testing.T) {
	origURL, _ := proberURL.Load().(string)
	defer proberURL.Store(origURL)

	SetPingProbeURL("")
	if got := currentPingProbeURL(); got != defaultPingProbeURL {
		t.Errorf("empty → %q, want default %q", got, defaultPingProbeURL)
	}

	// http:// with valid host accepted.
	SetPingProbeURL("http://example.com/probe")
	if got := currentPingProbeURL(); got != "http://example.com/probe" {
		t.Errorf("valid → %q, want %q", got, "http://example.com/probe")
	}

	// Garbage falls back to default.
	SetPingProbeURL("not a url at all")
	if got := currentPingProbeURL(); got != defaultPingProbeURL {
		t.Errorf("garbage → %q, want default", got)
	}

	// Unsupported scheme falls back to default.
	SetPingProbeURL("ftp://example.com/")
	if got := currentPingProbeURL(); got != defaultPingProbeURL {
		t.Errorf("ftp:// → %q, want default", got)
	}
}

// TestPingProbeSnapshot_Defaults sanity-checks the snapshot getter when
// nothing has happened yet.
func TestPingProbeSnapshot_Defaults(t *testing.T) {
	orig := proberState
	proberState = &pingProberState{}
	proberState.lastMs.Store(-1)
	defer func() { proberState = orig }()

	snap := PingProbeSnapshot()
	if snap.LastMs != -1 {
		t.Errorf("default LastMs = %d, want -1", snap.LastMs)
	}
	if snap.OK {
		t.Errorf("default OK = true, want false")
	}
	if snap.Failed {
		t.Errorf("default Failed = true, want false")
	}
	if snap.LastProbedAt != 0 {
		t.Errorf("default LastProbedAt = %d, want 0", snap.LastProbedAt)
	}
	if snap.URL == "" {
		t.Errorf("default URL is empty")
	}
}
