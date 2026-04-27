package bbcr

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	DefaultChurnRate  = 0.5
	DefaultChurnBurst = 6
	maxSafeChurnRate  = 1.0
)

var (
	ErrInvalidDialKey     = errors.New("bbcr: invalid dial key")
	ErrInvalidChurnConfig = errors.New("bbcr: invalid churn config")
	ErrHighChurnUnsafe    = errors.New("bbcr: high churn requires AllowHighChurn")
)

type DialKey struct{ ServerIP, SNI string }

type DialGate interface {
	Wait(ctx context.Context, key DialKey) error
	TryAcquire(key DialKey, now time.Time) bool
	Snapshot(key DialKey, now time.Time) (tokens float64, next time.Time)
}

type ChurnConfig struct {
	Rate           float64
	Burst          int
	AllowHighChurn bool
}

type ChurnGate struct {
	mu      sync.Mutex
	cfg     ChurnConfig
	clock   churnClock
	buckets map[DialKey]*churnBucket
}

type churnBucket struct {
	tokens float64
	last   time.Time
}

// churnClock is local to F0a; to be consolidated with bbcr.Clock after Phase A merges (see Phase 0 decomp v2 §3, Phase A spec Clock interface).
type churnClock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type realChurnClock struct{}

func (realChurnClock) Now() time.Time                         { return time.Now() }
func (realChurnClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func DefaultChurnConfig() ChurnConfig {
	return ChurnConfig{Rate: DefaultChurnRate, Burst: DefaultChurnBurst}
}
func NewChurnDialGate(cfg ChurnConfig) (*ChurnGate, error) {
	return newChurnDialGateWithClock(cfg, realChurnClock{})
}

func newChurnDialGateWithClock(cfg ChurnConfig, clock churnClock) (*ChurnGate, error) {
	if err := validateChurnConfig(cfg); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = realChurnClock{}
	}
	return &ChurnGate{cfg: cfg, clock: clock, buckets: make(map[DialKey]*churnBucket)}, nil
}

func validateChurnConfig(cfg ChurnConfig) error {
	if cfg.Rate <= 0 || math.IsNaN(cfg.Rate) || math.IsInf(cfg.Rate, 0) || cfg.Burst <= 0 {
		return ErrInvalidChurnConfig
	}
	if cfg.Rate > maxSafeChurnRate && !cfg.AllowHighChurn {
		return ErrHighChurnUnsafe
	}
	return nil
}

func (g *ChurnGate) Wait(ctx context.Context, key DialKey) error {
	if err := validateDialKey(key); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		now := g.clock.Now()
		if g.TryAcquire(key, now) {
			return nil
		}
		_, next := g.Snapshot(key, now)
		wait := next.Sub(now)
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-g.clock.After(wait):
		}
	}
}

func (g *ChurnGate) TryAcquire(key DialKey, now time.Time) bool {
	if validateDialKey(key) != nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	bucket := g.bucketLocked(key, now)
	g.refillLocked(bucket, now)
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	if bucket.tokens < 0 {
		bucket.tokens = 0
	}
	return true
}

func (g *ChurnGate) Snapshot(key DialKey, now time.Time) (float64, time.Time) {
	if validateDialKey(key) != nil {
		return 0, time.Time{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	bucket := g.bucketLocked(key, now)
	g.refillLocked(bucket, now)
	if bucket.tokens >= 1 {
		return bucket.tokens, now
	}
	wait := time.Duration(((1 - bucket.tokens) / g.cfg.Rate) * float64(time.Second))
	if wait <= 0 {
		wait = time.Nanosecond
	}
	return bucket.tokens, now.Add(wait)
}

func (g *ChurnGate) bucketLocked(key DialKey, now time.Time) *churnBucket {
	if bucket := g.buckets[key]; bucket != nil {
		return bucket
	}
	bucket := &churnBucket{tokens: float64(g.cfg.Burst), last: now}
	g.buckets[key] = bucket
	return bucket
}

func (g *ChurnGate) refillLocked(bucket *churnBucket, now time.Time) {
	if !now.After(bucket.last) {
		return
	}
	bucket.tokens += now.Sub(bucket.last).Seconds() * g.cfg.Rate
	if max := float64(g.cfg.Burst); bucket.tokens > max {
		bucket.tokens = max
	}
	bucket.last = now
}

func validateDialKey(key DialKey) error {
	if strings.TrimSpace(key.ServerIP) == "" || strings.TrimSpace(key.SNI) == "" {
		return ErrInvalidDialKey
	}
	return nil
}
