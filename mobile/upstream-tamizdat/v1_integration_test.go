package tamizdat

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type v1IntegrationRecorder struct {
	mu    sync.Mutex
	dests []string
}

func (r *v1IntegrationRecorder) add(dest string) {
	r.mu.Lock()
	r.dests = append(r.dests, dest)
	r.mu.Unlock()
}

func (r *v1IntegrationRecorder) count(dest string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, got := range r.dests {
		if got == dest {
			n++
		}
	}
	return n
}

type v1IntegrationOptions struct {
	bytesSoftCap int64
	dialer       DialFunc
}

func newV1IntegrationClient(t *testing.T, recorder *v1IntegrationRecorder) *Client {
	t.Helper()
	return newV1IntegrationClientWithOptions(t, recorder, v1IntegrationOptions{})
}

func newV1IntegrationClientWithOptions(t *testing.T, recorder *v1IntegrationRecorder, opts v1IntegrationOptions) *Client {
	t.Helper()
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		PrivateKey:    serverPriv,
		MasterShortID: shortID,
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
			if recorder != nil {
				recorder.add(destination)
			}
			_, _ = conn.Write([]byte("ok"))
			_, _ = io.Copy(io.Discard, conn)
		},
	})
	client, err := NewClient(ClientConfig{
		ServerAddr:               ln.Addr().String(),
		ServerName:               "test.example.com",
		PublicKey:                serverPub,
		ShortID:                  shortID,
		Fingerprint:              "chrome",
		DisableDefaultSecurity:   true,
		PoolVariant:              "v1",
		MinTransports:            1,
		MaxTransports:            1,
		BytesPerTransportSoftCap: opts.bytesSoftCap,
		Dialer:                   opts.dialer,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.handshakeLimiter = nil
	client.realtime.hysteresisMin = 20 * time.Millisecond
	client.realtime.hysteresisMax = 20 * time.Millisecond
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestV1_SteadyStateOneTransport(t *testing.T) {
	client := newV1IntegrationClient(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < 50; i++ {
		conn, err := client.DialContext(ctx, "tcp", fmt.Sprintf("bulk-%d.example:443", i))
		if err != nil {
			t.Fatalf("bulk DialContext %d: %v", i, err)
		}
		_ = conn.Close()
		if total, bulk, lite, _ := poolClassCounts(client.pool); total != 1 || bulk != 1 || lite != 0 {
			t.Fatalf("after sequential dial %d counts total/bulk/lite = %d/%d/%d, want 1/1/0", i, total, bulk, lite)
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 5)
	conns := make(chan net.Conn, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := client.DialContext(ctx, "tcp", fmt.Sprintf("parallel-%d.example:443", i))
			if err != nil {
				errCh <- err
				return
			}
			conns <- conn
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("parallel DialContext: %v", err)
		}
	}
	if total, bulk, lite, _ := poolClassCounts(client.pool); total != 1 || bulk != 1 || lite != 0 {
		t.Fatalf("parallel counts total/bulk/lite = %d/%d/%d, want 1/1/0", total, bulk, lite)
	}
	close(conns)
	for conn := range conns {
		_ = conn.Close()
	}
}

func TestV1_RealtimeFlipsToLiteAndBack(t *testing.T) {
	client := newV1IntegrationClient(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bulk, err := client.DialContext(ctx, "tcp", "bulk.example:443")
	if err != nil {
		t.Fatalf("initial bulk DialContext: %v", err)
	}
	_ = bulk.Close()
	initialBulk := findClassTransport(client.pool, TrafficBulk)
	if initialBulk == nil {
		t.Fatal("missing initial bulk transport")
	}
	if got := ShapeMode(initialBulk.shapeMode.Load()); got != ShapeFull {
		t.Fatalf("initial bulk shape = %s, want full", got)
	}

	realtime, err := client.DialContext(ctx, "tcp", "call.example:19302")
	if err != nil {
		t.Fatalf("realtime DialContext: %v", err)
	}
	if got := client.realtime.Mode(); got != ShapeLite {
		t.Fatalf("controller mode after realtime open = %s, want lite", got)
	}
	if total, bulkCount, liteCount, _ := poolClassCounts(client.pool); total != 1 || bulkCount != 1 || liteCount != 0 {
		t.Fatalf("V1 realtime counts total/bulk/lite = %d/%d/%d, want 1/1/0", total, bulkCount, liteCount)
	}
	// Tier 2.5: bulk-truba shape only flips on RTP-sticky-lock (proven realtime),
	// NOT on heuristic classification alone. TCP flows in particular never reach
	// applyPlanBRTPStickyLockLocked from the Observe path (early-return on
	// st.isTCP()), so a TCP-STUN-port realtime stream creates controller INTENT
	// (Mode=Lite) without committing the wire shape. Operator behaviour: GUI
	// lamp ○ until proven RTP arrives. UDP-path sticky-lock is exercised in
	// realtime_test.go directly via Observe.
	if got := ShapeMode(initialBulk.shapeMode.Load()); got != ShapeFull {
		t.Fatalf("bulk transport shape after heuristic TCP realtime open = %s, want full (Tier 2.5: TCP can't sticky-lock)", got)
	}
	if got := client.realtime.Detector.LockedRealtimeCount(); got != 0 {
		t.Fatalf("locked count after heuristic TCP realtime open = %d, want 0 (Tier 2.5: no RTP path)", got)
	}

	_ = realtime.Close()
	eventuallyV2(t, 500*time.Millisecond, func() bool {
		return client.realtime.Mode() == ShapeFull && ShapeMode(initialBulk.shapeMode.Load()) == ShapeFull
	})
}

func TestV1_RotationOnDoesNotExceedTwoTransports(t *testing.T) {
	var handshakes atomic.Int32
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		handshakes.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	client := newV1IntegrationClientWithOptions(t, nil, v1IntegrationOptions{bytesSoftCap: 4096, dialer: dialer})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, "tcp", "upload.example:443")
	if err != nil {
		t.Fatalf("initial DialContext: %v", err)
	}
	if _, err := conn.Write(make([]byte, 50*1024)); err != nil {
		t.Fatalf("upload write: %v", err)
	}
	old := findClassTransport(client.pool, TrafficBulk)
	if old == nil {
		t.Fatal("missing initial bulk transport")
	}
	eventuallyV2(t, 500*time.Millisecond, old.isDraining)

	freshConn, err := client.DialContext(ctx, "tcp", "after-rotation.example:443")
	if err != nil {
		t.Fatalf("fresh DialContext after cap: %v", err)
	}
	_ = freshConn.Close()
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("transport creates = %d, want 2 (initial + one replacement)", got)
	}
	if total, _, _, _ := poolClassCounts(client.pool); total > 2 {
		t.Fatalf("pool transports = %d, want <=2 during V1 rotation overlap", total)
	}
	_ = conn.Close()
	eventuallyV2(t, time.Second, func() bool {
		client.pool.cleanup()
		total, _, _, _ := poolClassCounts(client.pool)
		return total <= 1
	})
}

func TestV1_RotationDuringRealtimeCarriesLiteMode(t *testing.T) {
	client := newV1IntegrationClientWithOptions(t, nil, v1IntegrationOptions{bytesSoftCap: 4096})
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	realtime, err := client.DialContext(ctx, "tcp", "call.example:19302")
	if err != nil {
		t.Fatalf("realtime DialContext: %v", err)
	}
	old := findClassTransport(client.pool, TrafficBulk)
	if old == nil {
		t.Fatal("missing V1 bulk transport")
	}
	// Tier 2.5: heuristic TCP-STUN-port open does NOT flip bulk-truba shape
	// (no RTP sticky-lock from TCP). Old semantics asserted Lite here; updated
	// to Full to reflect the new invariant. Rotation-carries-mode still
	// validated below — fresh transport inherits intent from controller.
	if got := ShapeMode(old.shapeMode.Load()); got != ShapeFull {
		t.Fatalf("old transport shape after heuristic realtime open = %s, want full (Tier 2.5)", got)
	}

	bulk, err := client.DialContext(ctx, "tcp", "bulk-during-call.example:443")
	if err != nil {
		t.Fatalf("bulk DialContext during realtime: %v", err)
	}
	if _, err := bulk.Write(make([]byte, 50*1024)); err != nil {
		t.Fatalf("bulk write during realtime: %v", err)
	}
	eventuallyV2(t, 500*time.Millisecond, old.isDraining)

	freshConn, err := client.DialContext(ctx, "tcp", "fresh-during-call.example:443")
	if err != nil {
		t.Fatalf("fresh DialContext during realtime rotation: %v", err)
	}
	fresh := findNonDrainingBulkTransport(client.pool)
	if fresh == nil || fresh == old {
		t.Fatalf("fresh non-draining bulk = %p, old=%p", fresh, old)
	}
	// Tier 2.5: fresh transport spawned during heuristic-realtime + rotation
	// does NOT come up Lite, because lockedFlows is 0 (no proven RTP).
	// prepareV1BulkShapeMode now reads LockedRealtimeCount, not Mode().
	if got := ShapeMode(fresh.shapeMode.Load()); got != ShapeFull {
		t.Fatalf("fresh transport shape during heuristic realtime rotation = %s, want full (Tier 2.5)", got)
	}
	if total, _, _, _ := poolClassCounts(client.pool); total > 2 {
		t.Fatalf("pool transports = %d, want <=2 during realtime rotation", total)
	}

	time.Sleep(time.Second)
	_ = realtime.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := realtime.Write([]byte("still-open")); err != nil {
		t.Fatalf("realtime stream did not survive at least 1s after cap: %v", err)
	}
	_ = freshConn.Close()
	_ = bulk.Close()
	_ = realtime.Close()
	eventuallyV2(t, 700*time.Millisecond, func() bool {
		return client.realtime.Mode() == ShapeFull
	})
}

func findNonDrainingBulkTransport(p *connPool) *h2Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tr := range p.transports {
		if tr.class == TrafficBulk && !tr.isDraining() && !tr.isClosed() {
			return tr
		}
	}
	return nil
}

func TestV1_CoverSkippedDuringLite(t *testing.T) {
	recorder := &v1IntegrationRecorder{}
	client := newV1IntegrationClient(t, recorder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	realtime, err := client.DialContext(ctx, "tcp", "call.example:19302")
	if err != nil {
		t.Fatalf("realtime DialContext: %v", err)
	}
	const coverTarget = "mc.yandex.ru:443"
	targets := []string{coverTarget}
	d := &coverDriver{c: client, stop: make(chan struct{})}
	d.targets.Store(&targets)
	d.gapMin.Store(int64(5 * time.Millisecond))
	d.gapMax.Store(int64(5 * time.Millisecond))
	defer d.close()
	go d.run(ctx)

	time.Sleep(40 * time.Millisecond)
	if got := recorder.count(coverTarget); got != 0 {
		t.Fatalf("cover requests during V1 lite = %d, want 0", got)
	}
	_ = realtime.Close()
	eventuallyV2(t, 700*time.Millisecond, func() bool { return client.realtime.Mode() == ShapeFull })
	eventuallyV2(t, 700*time.Millisecond, func() bool { return recorder.count(coverTarget) > 0 })
}
