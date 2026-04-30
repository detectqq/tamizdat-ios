package samizdat

import (
	"crypto/sha256"
	"expvar"
	"sync"
	"time"
)

const (
	replayKeyLen        = 16
	defaultReplayWindow = 5 * time.Minute
	// replayHardCap (compass v2 §3.12 / §5.14): bumped from 4096 to 65536 so
	// a high-traffic Lantern server (1k auth/s) doesn't push out legitimate
	// new-client entries within the 5-minute window. Memory cost: 64K *
	// (16-byte key + ~32-byte time.Time map entry) = ~3 MB worst-case --
	// negligible vs server RSS (~10MB binary).
	replayHardCap = 65536
)

var (
	replayExpvarOnce sync.Once
	replayHits       *expvar.Int
	replayWindowSize *expvar.Int
	replayEvictions  *expvar.Int
)

func initReplayExpvars() {
	replayExpvarOnce.Do(func() {
		replayHits = new(expvar.Int)
		replayWindowSize = new(expvar.Int)
		replayEvictions = new(expvar.Int)
		expvar.Publish("samizdat.replay.hits", replayHits)
		expvar.Publish("samizdat.replay.window_size", replayWindowSize)
		expvar.Publish("samizdat.replay.evictions", replayEvictions)
	})
}

// replayGuard keeps a sliding window of recently-seen replay keys and rejects
// duplicates. P0.3 v1 replay keys are SHA-256(SessionID || eph_pub)[:16],
// computed by the caller before interacting with the guard. Legacy callers keep
// using check(sessionID), which hashes the SessionID into the same 16-byte key
// space to preserve duplicate-rejection semantics until ECDH-C wires v1 auth.
type replayGuard struct {
	mu      sync.Mutex
	seen    map[[replayKeyLen]byte]time.Time
	window  time.Duration
	hardCap int
	now     func() time.Time

	// lastReap records the last time we walked the map pruning expired entries
	// so steady-state auth traffic does not pay O(N) on every hit.
	lastReap time.Time
}

func newReplayGuard(window time.Duration) *replayGuard {
	if window <= 0 {
		window = defaultReplayWindow
	}
	return &replayGuard{
		seen:    make(map[[replayKeyLen]byte]time.Time),
		window:  window,
		hardCap: replayHardCap,
		now:     time.Now,
	}
}

// Seen reports whether key is already present inside the replay window. A true
// return means a replay attempt was observed. Seen does not insert missing keys;
// callers that need the legacy atomic "check and mark" behavior should use
// checkV1/check.
func (g *replayGuard) Seen(key [replayKeyLen]byte) bool {
	if g == nil {
		return false
	}
	initReplayExpvars()
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.currentTime()
	g.reapLocked(now, false)
	_, ok := g.seen[key]
	if ok {
		replayHits.Add(1)
	}
	return ok
}

// Insert adds key to the replay window with timestamp t. If the window exceeds
// the hard cap, the oldest entries are evicted until the cap is respected.
func (g *replayGuard) Insert(key [replayKeyLen]byte, t time.Time) {
	if g == nil {
		return
	}
	initReplayExpvars()
	g.mu.Lock()
	defer g.mu.Unlock()

	if t.IsZero() {
		t = g.currentTime()
	}
	g.reapLocked(t, true)
	g.seen[key] = t
	g.evictOverCapLocked()
	g.publishWindowSizeLocked()
}

// checkV1 returns true if key has not been seen inside the window and marks it
// as seen atomically. A false return means replay.
func (g *replayGuard) checkV1(key [replayKeyLen]byte) bool {
	return g.checkKey(key)
}

// check returns true if the SessionID has not been seen inside the window.
// A true return marks the SessionID as seen. A false return means replay.
// Deprecated: ECDH-C should compute SHA-256(SessionID || eph_pub)[:16] and call
// checkV1/Seen+Insert instead.
func (g *replayGuard) check(sessionID []byte) bool {
	return g.checkKey(legacyReplayKey(sessionID))
}

func (g *replayGuard) checkKey(key [replayKeyLen]byte) bool {
	if g == nil {
		return true
	}
	initReplayExpvars()
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.currentTime()
	g.reapLocked(now, false)
	if _, ok := g.seen[key]; ok {
		replayHits.Add(1)
		return false
	}
	g.seen[key] = now
	g.evictOverCapLocked()
	g.publishWindowSizeLocked()
	return true
}

func legacyReplayKey(sessionID []byte) [replayKeyLen]byte {
	digest := sha256.Sum256(sessionID)
	var key [replayKeyLen]byte
	copy(key[:], digest[:replayKeyLen])
	return key
}

func (g *replayGuard) currentTime() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

func (g *replayGuard) reapLocked(now time.Time, throttle bool) {
	if g.window <= 0 {
		g.window = defaultReplayWindow
	}
	if throttle && !g.lastReap.IsZero() && now.Sub(g.lastReap) <= g.window/4 {
		return
	}
	evicted := int64(0)
	for k, v := range g.seen {
		if now.Sub(v) > g.window {
			delete(g.seen, k)
			evicted++
		}
	}
	g.lastReap = now
	if evicted > 0 {
		replayEvictions.Add(evicted)
		g.publishWindowSizeLocked()
	}
}

func (g *replayGuard) evictOverCapLocked() {
	if g.hardCap <= 0 {
		g.hardCap = replayHardCap
	}
	evicted := int64(0)
	for len(g.seen) > g.hardCap {
		var oldestKey [replayKeyLen]byte
		var oldestTime time.Time
		first := true
		for k, v := range g.seen {
			if first || v.Before(oldestTime) {
				oldestKey = k
				oldestTime = v
				first = false
			}
		}
		delete(g.seen, oldestKey)
		evicted++
	}
	if evicted > 0 {
		replayEvictions.Add(evicted)
	}
}

func (g *replayGuard) publishWindowSizeLocked() {
	if replayWindowSize != nil {
		replayWindowSize.Set(int64(len(g.seen)))
	}
}

func (g *replayGuard) size() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
