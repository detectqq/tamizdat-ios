package tamizdat

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnPoolMaxTransportsCap(t *testing.T) {
	var created atomic.Int32
	pool := newConnPool(1, time.Minute, 1, 2, 0, -1, false, 0, func(ctx context.Context, class TrafficClass) (*h2Transport, error) {
		created.Add(1)
		return &h2Transport{maxStreams: 1}, nil
	})
	defer pool.close()

	if _, err := pool.getTransport(context.Background()); err != nil {
		t.Fatalf("first getTransport: %v", err)
	}
	if _, err := pool.getTransport(context.Background()); err != nil {
		t.Fatalf("second getTransport: %v", err)
	}
	_, err := pool.getTransport(context.Background())
	if err == nil || !strings.Contains(err.Error(), "MaxTransports") {
		t.Fatalf("third getTransport err = %v, want MaxTransports cap", err)
	}
	if got := created.Load(); got != 2 {
		t.Fatalf("created = %d, want 2", got)
	}
}

func TestConnPoolTopUpRespectsMaxTransports(t *testing.T) {
	var created atomic.Int32
	pool := newConnPool(100, time.Minute, 3, 3, 0, -1, false, 0, func(ctx context.Context, class TrafficClass) (*h2Transport, error) {
		created.Add(1)
		return &h2Transport{maxStreams: 100}, nil
	})
	defer pool.close()
	pool.maxTransports = 2 // exercise topUp's cap branch directly.

	pool.topUp()
	pool.mu.Lock()
	got := len(pool.transports)
	pool.mu.Unlock()
	if got != 2 {
		t.Fatalf("topUp transports = %d, want 2", got)
	}
	if created.Load() != 2 {
		t.Fatalf("created = %d, want 2", created.Load())
	}
}

func TestRandomizedBytesSoftCapRangeAndVaries(t *testing.T) {
	const base = int64(13312)
	seen := make(map[int64]struct{})
	for i := 0; i < 100; i++ {
		cap := randomizedBytesSoftCap(base)
		if cap < base || cap > base+1536 {
			t.Fatalf("cap %d outside [%d,%d]", cap, base, base+1536)
		}
		seen[cap] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("randomized caps did not vary: %v", seen)
	}
}
