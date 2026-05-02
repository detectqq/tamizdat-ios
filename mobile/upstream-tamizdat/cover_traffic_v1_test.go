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

type v1CoverRoundTripper struct {
	calls atomic.Int32
}

func (rt *v1CoverRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	go func() { _, _ = io.Copy(io.Discard, req.Body) }()
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("cover"))}, nil
}

func TestCoverLoopV1SkipsWhileRealtimeLite(t *testing.T) {
	rt := &v1CoverRoundTripper{}
	p := newConnPool(10, time.Hour, 1, 1, 0, 1, func(ctx context.Context, class TrafficClass) (*h2Transport, error) {
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
	defer p.close()
	controller := newRealtimeControllerWithConfig(newRealtimeDetector(), 10*time.Millisecond, 10*time.Millisecond)
	p.setRealtimeController(controller)
	client := &Client{pool: p, realtime: controller}
	targets := []string{"mc.yandex.ru:443"}
	d := &coverDriver{c: client, stop: make(chan struct{})}
	d.targets.Store(&targets)
	d.gapMin.Store(int64(5 * time.Millisecond))
	d.gapMax.Store(int64(5 * time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer d.close()

	flowID := controller.Open(TrafficRealtime)
	go d.run(ctx)
	time.Sleep(40 * time.Millisecond)
	if got := rt.calls.Load(); got != 0 {
		t.Fatalf("cover calls during lite = %d, want 0", got)
	}

	controller.Close(flowID)
	eventuallyV2(t, 250*time.Millisecond, func() bool { return controller.Mode() == ShapeFull })
	eventuallyV2(t, 250*time.Millisecond, func() bool { return rt.calls.Load() > 0 })
}
