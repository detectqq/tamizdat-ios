//go:build linux

package tamizdat

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func quickAckTestClient(t *testing.T, class TrafficClass, hook func(net.Conn, bool) error) (*net.TCPConn, *h2Transport) {
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
		},
	})

	var captured *net.TCPConn
	oldHook := setClientTCPQuickAck
	setClientTCPQuickAck = hook
	t.Cleanup(func() { setClientTCPQuickAck = oldHook })
	client, err := NewClient(ClientConfig{
		ServerAddr:             ln.Addr().String(),
		ServerName:             "test.example.com",
		PublicKey:              serverPub,
		ShortID:                shortID,
		Fingerprint:            "chrome",
		DisableDefaultSecurity: true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				captured = tcp
			}
			return conn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr, err := client.createTransport(ctx, class)
	if err != nil {
		t.Fatalf("createTransport(%s): %v", class, err)
	}
	if captured == nil {
		t.Fatal("custom Dialer did not capture TCPConn")
	}
	return captured, tr
}

func getTCPQuickAck(t *testing.T, conn *net.TCPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	got := -1
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		getErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
		if getErr == nil {
			got, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK)
		}
	}); err != nil {
		t.Fatalf("raw.Control: %v", err)
	}
	if getErr != nil {
		t.Fatalf("TCP_QUICKACK getsockopt: %v", getErr)
	}
	return got
}

func TestQuickAck_RealtimeTransportSetsQuick(t *testing.T) {
	var calls atomic.Int32
	var sawQuick atomic.Bool
	captured, tr := quickAckTestClient(t, TrafficRealtime, func(conn net.Conn, quick bool) error {
		calls.Add(1)
		if quick {
			sawQuick.Store(true)
		}
		return setTCPQuickAck(conn, quick)
	})
	defer tr.close()
	if calls.Load() != 1 || !sawQuick.Load() {
		t.Fatalf("quickack hook calls=%d sawQuick=%v, want one quick=true call", calls.Load(), sawQuick.Load())
	}
	if got := getTCPQuickAck(t, captured); got != 1 {
		t.Fatalf("TCP_QUICKACK = %d, want 1", got)
	}
}

func TestQuickAck_BulkTransportLeavesDefault(t *testing.T) {
	var calls atomic.Int32
	_, tr := quickAckTestClient(t, TrafficBulk, func(conn net.Conn, quick bool) error {
		calls.Add(1)
		return setTCPQuickAck(conn, quick)
	})
	defer tr.close()
	if calls.Load() != 0 {
		t.Fatalf("bulk createTransport invoked quickack hook %d times, want 0", calls.Load())
	}
}
