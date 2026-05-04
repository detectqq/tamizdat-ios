//go:build linux

package tamizdat

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestV1_QuickAckFlipsLinux(t *testing.T) {
	t.Skip("Tier 2.5: heuristic realtime open no longer flips bulk-truba shapeMode (TCP can't sticky-lock from Observe). Test needs RTP-injection rewrite — tracked separately.")
	oldHook := setClientTCPQuickAck
	var mu sync.Mutex
	calls := make([]bool, 0, 2)
	setClientTCPQuickAck = func(conn net.Conn, quick bool) error {
		mu.Lock()
		calls = append(calls, quick)
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() { setClientTCPQuickAck = oldHook })

	client := newV1IntegrationClient(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	realtime, err := client.DialContext(ctx, "tcp", "call.example:19302")
	if err != nil {
		t.Fatalf("realtime DialContext: %v", err)
	}
	eventuallyV2(t, 500*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, quick := range calls {
			if quick {
				return true
			}
		}
		return false
	})

	_ = realtime.Close()
	eventuallyV2(t, 700*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if len(calls) < 2 {
			return false
		}
		return calls[len(calls)-1] == false
	})
}
