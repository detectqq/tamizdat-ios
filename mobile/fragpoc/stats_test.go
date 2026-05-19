package fragpoc

import (
	"context"
	"testing"
)

func TestPortStatsReportsCumulativeActivity(t *testing.T) {
	c := &Client{
		dialPorts:       []int{31503, 31510, 31511, 31512},
		activePortCount: 2,
		opTokens:        make(chan struct{}, 4),
		downTokens:      make(chan struct{}, 3),
	}

	ctx := context.Background()
	if err := c.acquireOpToken(ctx); err != nil {
		t.Fatalf("acquireOpToken: %v", err)
	}
	if err := c.acquireDownToken(ctx); err != nil {
		t.Fatalf("acquireDownToken: %v", err)
	}
	c.openConns.Add(1)
	c.openConnsTotal.Add(7)

	stats := c.PortStats()
	if stats.DialPorts != 2 || stats.PoolPorts != 4 {
		t.Fatalf("ports = %d/%d, want 2/4", stats.DialPorts, stats.PoolPorts)
	}
	if stats.OpenConns != 1 || stats.OpenConnsTotal != 7 {
		t.Fatalf("open conns = live %d total %d, want live 1 total 7", stats.OpenConns, stats.OpenConnsTotal)
	}
	if stats.OpTokens != 1 || stats.OpTokenCap != 4 || stats.OpTokensTotal != 1 {
		t.Fatalf("op tokens = live %d cap %d total %d, want live 1 cap 4 total 1", stats.OpTokens, stats.OpTokenCap, stats.OpTokensTotal)
	}
	if stats.DownTokens != 1 || stats.DownTokenCap != 3 || stats.DownPollsTotal != 1 {
		t.Fatalf("down tokens = live %d cap %d total %d, want live 1 cap 3 total 1", stats.DownTokens, stats.DownTokenCap, stats.DownPollsTotal)
	}

	c.releaseOpToken(ctx)
	c.releaseDownToken()
	c.openConns.Add(-1)

	stats = c.PortStats()
	if stats.OpenConns != 0 || stats.OpTokens != 0 || stats.DownTokens != 0 {
		t.Fatalf("live counters after release = conn %d op %d down %d, want all 0", stats.OpenConns, stats.OpTokens, stats.DownTokens)
	}
	if stats.OpenConnsTotal != 7 || stats.OpTokensTotal != 1 || stats.DownPollsTotal != 1 {
		t.Fatalf("totals after release = dials %d ops %d down %d, want 7/1/1", stats.OpenConnsTotal, stats.OpTokensTotal, stats.DownPollsTotal)
	}
}
