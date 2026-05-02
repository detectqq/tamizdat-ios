package tamizdat

import (
	"encoding/hex"
	"testing"
)

func shortIDFromHex(t *testing.T, s string) [8]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	if len(b) != 8 {
		t.Fatalf("hex %q decoded to %d bytes, want 8", s, len(b))
	}
	var id [8]byte
	copy(id[:], b)
	return id
}

func TestHKDFRoundTripDeterministic(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	p1 := DeriveShortIDPool(master, "ep-2026-05-01-rotated", 16)
	p2 := DeriveShortIDPool(master, "ep-2026-05-01-rotated", 16)
	if len(p1) != 16 || len(p2) != 16 {
		t.Fatalf("pool lengths = %d/%d, want 16/16", len(p1), len(p2))
	}
	for i := range p1 {
		if p1[i] != p2[i] {
			t.Fatalf("entry %d drifted: %x != %x", i, p1[i], p2[i])
		}
	}
	if got := DeriveShortIDPool(master, "ep-2026-05-01-rotated", 0); len(got) != 0 {
		t.Fatalf("size 0 returned %d entries, want 0", len(got))
	}
}

func TestHKDFEpochSeparation(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	a := DeriveShortIDPool(master, "ep-a", 100)
	b := DeriveShortIDPool(master, "ep-b", 100)
	seen := make(map[[8]byte]struct{}, len(a))
	for _, id := range a {
		seen[id] = struct{}{}
	}
	for i, id := range b {
		if _, ok := seen[id]; ok {
			t.Fatalf("epoch pools overlapped at b[%d]=%x", i, id)
		}
	}
}

func TestHKDFTestVectors(t *testing.T) {
	cases := []struct {
		masterHex string
		epochKey  string
		index     int
		wantHex   string
	}{
		{"0001020304050607", "ep-2026-05-01-rotated", 0, "a20a3598400b2c6d"},
		{"0001020304050607", "ep-2026-05-01-rotated", 1, "1b567f05a87cdd50"},
		{"d1b122782219759f", "ep-2026-05-01-rotated-a1b2c3d4", 42, "46a1a2b7b66bb3a7"},
	}
	for _, tc := range cases {
		master := shortIDFromHex(t, tc.masterHex)
		pool := DeriveShortIDPool(master, tc.epochKey, tc.index+1)
		got := hex.EncodeToString(pool[tc.index][:])
		if got != tc.wantHex {
			t.Fatalf("DeriveShortIDPool(%s,%q)[%d]=%s, want %s", tc.masterHex, tc.epochKey, tc.index, got, tc.wantHex)
		}
	}
}

func TestHKDFSizePanics(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	for _, size := range []int{-1, 1001} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("DeriveShortIDPool size %d did not panic", size)
				}
			}()
			_ = DeriveShortIDPool(master, "ep", size)
		}()
	}
}

func TestPoolAcceptCurrentEpoch(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	p := newShortIDPool(master, 2)
	p.Rotate("ep-current", 8)
	for _, id := range DeriveShortIDPool(master, "ep-current", 8) {
		if !p.Accept(id) {
			t.Fatalf("current epoch shortID %x rejected", id)
		}
	}
}

func TestPoolAcceptMaster(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	p := newShortIDPool(master, 2)
	if !p.Accept(master) {
		t.Fatal("master shortID rejected before any rotation")
	}
	p.Rotate("ep-current", 8)
	if !p.Accept(master) {
		t.Fatal("master shortID rejected after rotation")
	}
}

func TestPoolAcceptGraceWindow(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	p := newShortIDPool(master, 1)
	old := DeriveShortIDPool(master, "ep-old", 1)[0]
	p.Rotate("ep-old", 1)
	p.Rotate("ep-new", 1)
	if !p.Accept(old) {
		t.Fatal("previous epoch within grace window rejected")
	}
	p.Rotate("ep-newer", 1)
	if p.Accept(old) {
		t.Fatal("epoch older than grace window accepted")
	}
}

func TestPoolRotateFIFO(t *testing.T) {
	master := shortIDFromHex(t, "0001020304050607")
	p := newShortIDPool(master, 2)
	ids := [][8]byte{
		DeriveShortIDPool(master, "ep-1", 1)[0],
		DeriveShortIDPool(master, "ep-2", 1)[0],
		DeriveShortIDPool(master, "ep-3", 1)[0],
	}
	p.Rotate("ep-1", 1)
	p.Rotate("ep-2", 1)
	p.Rotate("ep-3", 1)
	if !p.Accept(ids[0]) || !p.Accept(ids[1]) || !p.Accept(ids[2]) {
		t.Fatalf("expected current plus two previous epochs to be accepted")
	}
	p.Rotate("ep-4", 1)
	if p.Accept(ids[0]) {
		t.Fatalf("oldest previous epoch was not dropped FIFO")
	}
	if !p.Accept(ids[1]) || !p.Accept(ids[2]) {
		t.Fatalf("newer previous epochs should remain accepted")
	}
}
