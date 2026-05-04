package tamizdat

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDefaultCoverTargets verifies the diversified cover-target pool is
// non-empty and every entry is host:port form on the canonical TLS port 443.
//
// Cover targets are by-design HTTPS endpoints (we mimic a browser making
// background fetches to RU CDN/analytics sites) so :443 is a hard
// requirement, not over-fitting.
//
// We additionally check for at least one subdomain entry (e.g. mc.yandex.ru)
// to enforce traffic-shape diversity (compass v3 cleanup: avoid the old
// 5-homepage default that produced a homogeneous flow profile).
func TestDefaultCoverTargets(t *testing.T) {
	got := defaultCoverTargets()
	if len(got) < 5 {
		t.Fatalf("defaultCoverTargets returned %d entries, want >=5 for diversity", len(got))
	}
	for _, target := range got {
		if !strings.HasSuffix(target, ":443") {
			t.Errorf("cover target %q must end in :443 (cover traffic must look like HTTPS)", target)
		}
		host := strings.TrimSuffix(target, ":443")
		if host == "" || strings.ContainsAny(host, " /") {
			t.Errorf("cover target %q has malformed host part", target)
		}
	}
	hasSubdomain := false
	for _, target := range got {
		host := strings.TrimSuffix(target, ":443")
		if strings.Count(host, ".") >= 2 {
			hasSubdomain = true
			break
		}
	}
	if !hasSubdomain {
		t.Error("defaultCoverTargets is too homogeneous: expected at least one subdomain for traffic-shape diversity")
	}
}

// TestCoverGapBounds verifies the gap helper stays within configured bounds.
func TestCoverGapBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		gap := coverRandUint64n(uint64(coverGapMax - coverGapMin))
		if gap >= uint64(coverGapMax-coverGapMin) {
			t.Errorf("iter %d: gap %d >= max %d", i, gap, coverGapMax-coverGapMin)
		}
	}
}

type coverClassRoundTripper struct {
	pool   *connPool
	target string
	saw    atomic.Bool
	err    atomic.Value
}

func (rt *coverClassRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	go func() { _, _ = io.Copy(io.Discard, req.Body) }()
	if req.Host == rt.target {
		rt.saw.Store(true)
		bulkStreams := 0
		liteStreams := 0
		rt.pool.mu.Lock()
		for _, tr := range rt.pool.transports {
			switch tr.class {
			case TrafficRealtime:
				liteStreams += tr.streamCount()
			default:
				bulkStreams += tr.streamCount()
			}
		}
		rt.pool.mu.Unlock()
		if liteStreams != 1 || bulkStreams == 0 {
			rt.err.Store("cover did not land on bulk while preserving existing lite stream")
		}
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("cover"))}, nil
}

func TestPool_CoverNeverLandsOnLite(t *testing.T) {
	const target = "mc.yandex.ru:443"
	rt := &coverClassRoundTripper{target: target}
	p := newConnPool(10, time.Hour, 1, 2, 0, -1, false, 0, func(ctx context.Context, class TrafficClass) (*h2Transport, error) {
		tr := &h2Transport{
			maxStreams:   10,
			serverAddr:   "tamizdat.test:443",
			localAddr:    &streamAddr{"tcp", "local"},
			remoteAddr:   &streamAddr{"tcp", "remote"},
			h2Roundtrip:  rt,
			drainTimeout: 10 * time.Millisecond,
		}
		prepareTransportForClass(tr, class)
		tr.touch()
		return tr, nil
	})
	rt.pool = p
	defer p.close()
	p.topUp()

	lite, err := p.getTransportForClass(context.Background(), TrafficRealtime)
	if err != nil {
		t.Fatalf("get lite: %v", err)
	}
	defer lite.releaseStreamSlot()
	c := &Client{pool: p}
	d := &coverDriver{c: c}
	d.coverOnce(context.Background(), target)
	if !rt.saw.Load() {
		t.Fatal("cover round tripper did not see cover target")
	}
	if v := rt.err.Load(); v != nil {
		t.Fatal(v)
	}
	if got := lite.streamCount(); got != 1 {
		t.Fatalf("lite streamCount after cover = %d, want existing realtime stream only", got)
	}
}
