package tamizdat

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"expvar"
	"fmt"
	"sync"
	"testing"
	"time"
)

func replayTestKey(seed byte) [16]byte {
	var key [16]byte
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func replayKeyFromSessionAndEphemeral(sessionID, ephemeralPublicKey []byte) [16]byte {
	digest := sha256.Sum256(append(append([]byte{}, sessionID...), ephemeralPublicKey...))
	var key [16]byte
	copy(key[:], digest[:16])
	return key
}

func resetReplayExpvarsForTest() {
	initReplayExpvars()
	replayHits.Set(0)
	replayWindowSize.Set(0)
	replayEvictions.Set(0)
}

func TestReplayKeyV1SHA256TruncatedVectorAndRandomCollisionSmoke(t *testing.T) {
	sessionID := make([]byte, 32)
	ephemeralPublicKey := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i)
		ephemeralPublicKey[i] = byte(0xa0 + i)
	}
	key := replayKeyFromSessionAndEphemeral(sessionID, ephemeralPublicKey)
	if got, want := hex.EncodeToString(key[:]), "60dcbc828060c044579c4b6c671582e3"; got != want {
		t.Fatalf("SHA-256(SessionID || eph_pub)[:16] = %s, want %s", got, want)
	}

	seen := make(map[[16]byte]struct{}, 10000)
	buf := make([]byte, 64)
	for i := 0; i < 10000; i++ {
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		key := replayKeyFromSessionAndEphemeral(buf[:32], buf[32:])
		if _, ok := seen[key]; ok {
			t.Fatalf("unexpected 16-byte replay-key collision after %d randomized inputs: %x", i+1, key)
		}
		seen[key] = struct{}{}
	}
}

func TestReplayGuardInsertAndSeen(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	now := time.Unix(1000, 0)
	g.now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		g.Insert(replayTestKey(byte(i)), now)
	}
	for i := 0; i < 100; i++ {
		if !g.Seen(replayTestKey(byte(i))) {
			t.Fatalf("key %d was not seen after insert", i)
		}
	}
	if g.Seen(replayTestKey(200)) {
		t.Fatal("random non-inserted key reported as seen")
	}
	if got := expvar.Get("tamizdat.replay.hits").String(); got != "100" {
		t.Fatalf("hits counter = %s, want 100", got)
	}
	if got := expvar.Get("tamizdat.replay.window_size").String(); got != "100" {
		t.Fatalf("window_size counter = %s, want 100", got)
	}
}

func TestReplayGuardWindowExpiryFiveMinutes(t *testing.T) {
	resetReplayExpvarsForTest()
	base := time.Unix(0, 0)
	g := newReplayGuard(0)
	now := base
	g.now = func() time.Time { return now }
	key := replayTestKey(1)
	g.Insert(key, base)

	now = base.Add(4*time.Minute + 59*time.Second)
	if !g.Seen(key) {
		t.Fatal("key expired before five-minute replay window elapsed")
	}

	now = base.Add(5*time.Minute + time.Second)
	if g.Seen(key) {
		t.Fatal("key still seen after five-minute replay window elapsed")
	}
	if got := expvar.Get("tamizdat.replay.evictions").String(); got != "1" {
		t.Fatalf("evictions counter = %s, want 1", got)
	}
}

func TestReplayGuardHardCapEvictsOldest(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	base := time.Unix(1000, 0)
	now := base
	g.now = func() time.Time { return now }
	oldest := replayTestKey(0)
	g.Insert(oldest, base)
	for i := 1; i <= replayHardCap; i++ {
		var key [16]byte
		copy(key[:], []byte(fmt.Sprintf("key-%08d----", i)))
		g.Insert(key, base.Add(time.Duration(i)*time.Nanosecond))
	}
	if g.Seen(oldest) {
		t.Fatal("oldest key still present after inserting hard-cap+1 entries")
	}
	if got := g.size(); got != replayHardCap {
		t.Fatalf("window size = %d, want %d", got, replayHardCap)
	}
	if got := expvar.Get("tamizdat.replay.evictions").String(); got != "1" {
		t.Fatalf("evictions counter = %s, want 1", got)
	}
	if got := expvar.Get("tamizdat.replay.window_size").String(); got != fmt.Sprint(replayHardCap) {
		t.Fatalf("window_size counter = %s, want %d", got, replayHardCap)
	}
}

func TestReplayGuardCheckV1AllowsSharedSessionIDDifferentEphemeral(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	sessionID := make([]byte, 32)
	ephemeralA := make([]byte, 32)
	ephemeralB := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = byte(i)
		ephemeralA[i] = byte(0x40 + i)
		ephemeralB[i] = byte(0x80 + i)
	}
	keyA := replayKeyFromSessionAndEphemeral(sessionID, ephemeralA)
	keyB := replayKeyFromSessionAndEphemeral(sessionID, ephemeralB)
	if !g.checkV1(keyA) {
		t.Fatal("first v1 replay key was rejected")
	}
	if !g.checkV1(keyB) {
		t.Fatal("distinct eph_pub with shared SessionID should use a distinct replay key bucket")
	}
	if g.checkV1(keyA) {
		t.Fatal("duplicate v1 replay key was accepted")
	}
}

func TestReplayGuardConcurrency(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				var key [16]byte
				copy(key[:], []byte(fmt.Sprintf("%02d-%012d", worker, i)))
				if !g.checkV1(key) {
					t.Errorf("fresh key rejected for worker=%d i=%d", worker, i)
				}
			}
		}()
	}
	wg.Wait()
	// After hardcap was bumped from 4096 to 65536, 16 workers x 1000 keys = 16000
	// no longer triggers cap eviction. Assert the cap is an upper bound; a separate
	// test (TestReplayGuardEvictsAtCap) validates eviction with a small cap.
	if got := g.size(); got > replayHardCap {
		t.Fatalf("window size = %d > hard cap %d", got, replayHardCap)
	}

	var replayed [16]byte
	copy(replayed[:], []byte("same-key--------"))
	accepted := 0
	wg = sync.WaitGroup{}
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.checkV1(replayed) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("same-key race accepted %d calls, want exactly 1", accepted)
	}
}
// TestReplayGuardEvictsAtCap verifies that the LRU eviction triggers when
// the window exceeds the configured hard cap. Uses a manually-constructed
// guard with a tiny capacity so we don't have to insert 65k keys.
func TestReplayGuardEvictsAtCap(t *testing.T) {
	resetReplayExpvarsForTest()
	g := newReplayGuard(5 * time.Minute)
	g.hardCap = 8 // override default for the test only
	for i := 0; i < 100; i++ {
		var key [16]byte
		copy(key[:], []byte(fmt.Sprintf("key-%012d", i)))
		_ = g.checkV1(key)
	}
	if got := g.size(); got > g.hardCap {
		t.Fatalf("size %d > hardCap %d (LRU eviction did not run)", got, g.hardCap)
	}
}
