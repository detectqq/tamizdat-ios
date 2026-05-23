package tamizdat

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// rttProbe periodically dials a fixed reference target through the tunnel
// and records the connect-time as a tunnel-RTT proxy. Each sample is
// tagged with the bulk-truba's current shape (Bulk vs Lite). Operator-
// visible: see the per-shape p50/p99 split via expvar — direct evidence
// of how much latency the obfuscation costs.
type rttProbe struct {
	client     *Client
	target     string        // e.g. "1.1.1.1:80"
	period     time.Duration // e.g. 1s
	timeout    time.Duration // per-dial timeout
	maxSamples int           // ring size per shape
	cancel     context.CancelFunc

	mu          sync.Mutex
	samplesLite []time.Duration
	samplesBulk []time.Duration
}

func newRTTProbe(c *Client) *rttProbe {
	return &rttProbe{
		client:     c,
		target:     "1.1.1.1:80",
		period:     1 * time.Second,
		timeout:    3 * time.Second,
		maxSamples: 60,
	}
}

func (p *rttProbe) start() {
	if p == nil || p.client == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.run(ctx)
}

func (p *rttProbe) stop() {
	if p == nil || p.cancel == nil {
		return
	}
	p.cancel()
}

func (p *rttProbe) run(ctx context.Context) {
	t := time.NewTicker(p.period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.doProbe(ctx)
	}
}

func (p *rttProbe) doProbe(ctx context.Context) {
	dctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	start := time.Now()
	conn, err := p.client.DialContext(dctx, "tcp", p.target)
	rtt := time.Since(start)
	if err != nil {
		return
	}
	_ = conn.Close()
	shape := p.client.RealShapeMode()
	p.mu.Lock()
	if shape == "lite" {
		p.samplesLite = appendCap(p.samplesLite, rtt, p.maxSamples)
	} else {
		p.samplesBulk = appendCap(p.samplesBulk, rtt, p.maxSamples)
	}
	p.mu.Unlock()
}

func appendCap(s []time.Duration, v time.Duration, cap int) []time.Duration {
	s = append(s, v)
	if len(s) > cap {
		s = s[len(s)-cap:]
	}
	return s
}

// Snapshot returns p50 (in ms, integer rounded) for both shape modes plus
// most-recent sample. Returns -1 for any bucket with no samples yet.
type RTTProbeStats struct {
	LiteP50Ms int64
	BulkP50Ms int64
	LiteCount int
	BulkCount int
	LastMs    int64
	LastShape string
}

func (p *rttProbe) Snapshot() RTTProbeStats {
	if p == nil {
		return RTTProbeStats{LiteP50Ms: -1, BulkP50Ms: -1, LastMs: -1}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := RTTProbeStats{
		LiteP50Ms: -1,
		BulkP50Ms: -1,
		LastMs:    -1,
		LiteCount: len(p.samplesLite),
		BulkCount: len(p.samplesBulk),
	}
	if len(p.samplesLite) > 0 {
		st.LiteP50Ms = percentileMs(p.samplesLite, 50)
	}
	if len(p.samplesBulk) > 0 {
		st.BulkP50Ms = percentileMs(p.samplesBulk, 50)
	}
	// "Last" = latest of either bucket
	var lastT time.Duration
	var lastShape string
	if len(p.samplesLite) > 0 {
		lastT = p.samplesLite[len(p.samplesLite)-1]
		lastShape = "lite"
	}
	if len(p.samplesBulk) > 0 {
		// We don't track ordering across buckets — pick the bucket with most recent based on which has a sample.
		// Conservative: prefer bulk if we don't know.
		lastT = p.samplesBulk[len(p.samplesBulk)-1]
		lastShape = "bulk"
	}
	st.LastMs = int64(lastT / time.Millisecond)
	st.LastShape = lastShape
	return st
}

func percentileMs(d []time.Duration, p int) int64 {
	if len(d) == 0 {
		return 0
	}
	tmp := make([]time.Duration, len(d))
	copy(tmp, d)
	sort.Slice(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })
	idx := (len(tmp) * p) / 100
	if idx >= len(tmp) {
		idx = len(tmp) - 1
	}
	return int64(tmp[idx] / time.Millisecond)
}

// dummy-use net package
var _ = net.Dialer{}
