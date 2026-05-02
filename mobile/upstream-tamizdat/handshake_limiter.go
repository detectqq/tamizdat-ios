package tamizdat

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrHandshakeRateLimited = errors.New("tamizdat: handshake rate limited")

const (
	defaultHandshakeLimit  = 3
	defaultHandshakeWindow = 20 * time.Second
)

type handshakeLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	events map[string][]time.Time
}

func newHandshakeLimiter() *handshakeLimiter {
	return newHandshakeLimiterWithConfig(defaultHandshakeLimit, defaultHandshakeWindow)
}

func newHandshakeLimiterWithConfig(limit int, window time.Duration) *handshakeLimiter {
	if limit <= 0 {
		limit = defaultHandshakeLimit
	}
	if window <= 0 {
		window = defaultHandshakeWindow
	}
	return &handshakeLimiter{
		limit:  limit,
		window: window,
		now:    time.Now,
		events: make(map[string][]time.Time),
	}
}

func (l *handshakeLimiter) Wait(ctx context.Context, key string) error {
	if l == nil {
		return nil
	}
	if key == "" {
		key = "default"
	}
	for {
		wait := l.reserveOrDelay(key)
		if wait <= 0 {
			return nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ErrHandshakeRateLimited
		case <-timer.C:
		}
	}
}

func (l *handshakeLimiter) reserveOrDelay(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.currentTime()
	cutoff := now.Add(-l.window)
	events := l.events[key]
	keep := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	if len(keep) == 0 {
		delete(l.events, key)
	} else {
		l.events[key] = keep
	}
	if len(keep) < l.limit {
		l.events[key] = append(keep, now)
		return 0
	}
	oldest := keep[0]
	wait := oldest.Add(l.window).Sub(now)
	if wait < 0 {
		return 0
	}
	return wait
}

func (l *handshakeLimiter) currentTime() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}
