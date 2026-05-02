package tamizdat

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type v2DestRecorder struct {
	mu    sync.Mutex
	dests []string
}

func (r *v2DestRecorder) add(dest string) {
	r.mu.Lock()
	r.dests = append(r.dests, dest)
	r.mu.Unlock()
}

func (r *v2DestRecorder) contains(dest string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, got := range r.dests {
		if got == dest {
			return true
		}
	}
	return false
}

func newV2IntegrationClient(t *testing.T, dialer DialFunc, recorder *v2DestRecorder) *Client {
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
		},
	})
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		ServerName:             "test.example.com",
		PublicKey:              serverPub,
		ShortID:                shortID,
		Fingerprint:            "chrome",
		DisableDefaultSecurity: true,
		PoolVariant:            "v2",
		Dialer:                 dialer,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.handshakeLimiter = nil
	t.Cleanup(func() { _ = client.Close() })
	client.pool.liteCloseMin = 30 * time.Millisecond
	client.pool.liteCloseMax = 30 * time.Millisecond
	return client
}

func TestV2_RealtimeStreamHasOwnTransport(t *testing.T) {
	client := newV2IntegrationClient(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bulk, err := client.DialContext(ctx, "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("bulk DialContext: %v", err)
	}
	defer bulk.Close()
	pc, err := client.DialUDP(ctx, "8.8.8.8:3478")
	if err != nil {
		t.Fatalf("DialUDP realtime: %v", err)
	}
	if total, bulkCount, liteCount, _ := poolClassCounts(client.pool); total != 2 || bulkCount != 1 || liteCount != 1 {
		t.Fatalf("pool counts = %d/%d/%d, want 2/1/1", total, bulkCount, liteCount)
	}
	_ = pc.Close()
	eventuallyV2(t, 500*time.Millisecond, func() bool {
		total, bulkCount, liteCount, _ := poolClassCounts(client.pool)
		return total == 1 && bulkCount == 1 && liteCount == 0
	})
}

func TestV2_HighThroughputBulkRotates_RealtimeStable(t *testing.T) {
	client := newV2IntegrationClient(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bulkConn, err := client.DialContext(ctx, "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("initial bulk DialContext: %v", err)
	}
	pc, err := client.DialUDP(ctx, "8.8.8.8:3478")
	if err != nil {
		t.Fatalf("DialUDP realtime: %v", err)
	}
	defer pc.Close()
	lite := client.pool.liteTransport
	for i := 0; i < 2; i++ {
		oldBulk := findClassTransport(client.pool, TrafficBulk)
		if oldBulk == nil {
			t.Fatalf("rotation %d missing bulk", i)
		}
		oldBulk.markDraining()
		_ = bulkConn.Close()
		eventuallyV2(t, 500*time.Millisecond, func() bool { return oldBulk.streamCount() == 0 })
		client.pool.cleanup()
		bulkConn, err = client.DialContext(ctx, "tcp", "example.org:443")
		if err != nil {
			t.Fatalf("rotation %d fresh bulk DialContext: %v", i, err)
		}
		if client.pool.liteTransport != lite || lite.isDraining() || lite.isClosed() {
			t.Fatalf("rotation %d changed lite transport", i)
		}
	}
	_ = bulkConn.Close()
}

func TestV2_NoCoverOnLite(t *testing.T) {
	recorder := &v2DestRecorder{}
	client := newV2IntegrationClient(t, nil, recorder)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := client.DialUDP(ctx, "8.8.8.8:3478")
	if err != nil {
		t.Fatalf("DialUDP realtime: %v", err)
	}
	defer pc.Close()
	lite := client.pool.liteTransport
	d := &coverDriver{c: client}
	const coverTarget = "mc.yandex.ru:443"
	d.coverOnce(ctx, coverTarget)
	if !recorder.contains(coverTarget) {
		t.Fatalf("server did not observe cover target %s", coverTarget)
	}
	if client.pool.liteTransport != lite || lite.streamCount() != 1 {
		t.Fatalf("cover changed or used lite transport; lite ptr=%p/%p streams=%d", client.pool.liteTransport, lite, lite.streamCount())
	}
}

func TestV2_HysteresisHonoursOpUseCase(t *testing.T) {
	var handshakes atomic.Int32
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		handshakes.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	client := newV2IntegrationClient(t, dialer, nil)
	client.pool.liteCloseMin = 60 * time.Millisecond
	client.pool.liteCloseMax = 60 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc1, err := client.DialUDP(ctx, "8.8.8.8:3478")
	if err != nil {
		t.Fatalf("first realtime DialUDP: %v", err)
	}
	_ = pc1.Close()
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("handshakes after first realtime = %d, want 1", got)
	}
	time.Sleep(20 * time.Millisecond)
	pc2, err := client.DialUDP(ctx, "8.8.8.8:3478")
	if err != nil {
		t.Fatalf("second realtime DialUDP during hysteresis: %v", err)
	}
	_ = pc2.Close()
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("handshakes during hysteresis = %d, want still 1", got)
	}
	eventuallyV2(t, 500*time.Millisecond, func() bool {
		_, _, liteCount, _ := poolClassCounts(client.pool)
		return liteCount == 0
	})
	pc3, err := client.DialUDP(ctx, "8.8.8.8:3478")
	if err != nil {
		t.Fatalf("third realtime DialUDP after hysteresis: %v", err)
	}
	defer pc3.Close()
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("handshakes after hysteresis = %d, want 2", got)
	}
}
