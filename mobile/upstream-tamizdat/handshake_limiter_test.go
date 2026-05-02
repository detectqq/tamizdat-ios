package tamizdat

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHandshakeLimiterBlocksFourthUntilWindowSlides(t *testing.T) {
	lim := newHandshakeLimiterWithConfig(3, 50*time.Millisecond)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := lim.Wait(ctx, "203.0.113.10:443"); err != nil {
			t.Fatalf("Wait #%d: %v", i+1, err)
		}
	}

	start := time.Now()
	if err := lim.Wait(ctx, "203.0.113.10:443"); err != nil {
		t.Fatalf("fourth Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("fourth Wait returned too early: %s", elapsed)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("fourth Wait blocked too long: %s", elapsed)
	}
}

func TestHandshakeLimiterContextCancelReturnsRateLimited(t *testing.T) {
	lim := newHandshakeLimiterWithConfig(1, time.Second)
	if err := lim.Wait(context.Background(), "203.0.113.20:443"); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := lim.Wait(ctx, "203.0.113.20:443")
	if !errors.Is(err, ErrHandshakeRateLimited) {
		t.Fatalf("Wait after cancel = %v, want ErrHandshakeRateLimited", err)
	}
}
