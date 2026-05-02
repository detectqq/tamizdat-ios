package tamizdat

import (
	"crypto/x509"
	"testing"
)

func TestPadCertChain_AddsAtLeastTargetBytes(t *testing.T) {
	// Start with a single 1-byte "leaf" placeholder (we don't need a real cert
	// for size accounting; padCertChain operates on [][]byte).
	leaf := [][]byte{make([]byte, 1024)}
	out, err := padCertChain(leaf, 3000, 3)
	if err != nil {
		t.Fatalf("padCertChain: %v", err)
	}
	if len(out) < len(leaf)+1 {
		t.Errorf("expected at least one padding cert, got chain length %d", len(out))
	}

	// Sum of padding bytes (excluding leaf).
	added := 0
	for _, c := range out[len(leaf):] {
		added += len(c)
	}
	if added < 3000 {
		t.Errorf("padding total %d < target 3000", added)
	}
}

func TestPadCertChain_GeneratesValidX509(t *testing.T) {
	out, err := padCertChain([][]byte{}, 1000, 1)
	if err != nil {
		t.Fatalf("padCertChain: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no padding cert produced")
	}
	// Each padding cert must be parseable as X.509.
	for i, der := range out {
		_, err := x509.ParseCertificate(der)
		if err != nil {
			t.Errorf("padding cert #%d not valid X.509: %v", i, err)
		}
	}
}

func TestPadCertChain_RandomizedSubjects(t *testing.T) {
	// Two padding chains generated separately must not be byte-identical.
	a, err := padCertChain([][]byte{}, 500, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := padCertChain([][]byte{}, 500, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) > 0 && len(b) > 0 && string(a[0]) == string(b[0]) {
		t.Error("two padding cert chains have identical leaf cert bytes — randomization failed")
	}
}
