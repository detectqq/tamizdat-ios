//go:build linux

package tamizdat

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type quickAckNetConner struct {
	net.Conn
	underlying net.Conn
}

func (c quickAckNetConner) NetConn() net.Conn { return c.underlying }

func newTCPConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	acceptCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conn
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var d net.Dialer
	clientConn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var serverConn net.Conn
	select {
	case serverConn = <-acceptCh:
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case <-ctx.Done():
		t.Fatalf("accept timeout: %v", ctx.Err())
	}
	clientTCP, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("client conn type %T, want *net.TCPConn", clientConn)
	}
	serverTCP, ok := serverConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("server conn type %T, want *net.TCPConn", serverConn)
	}
	t.Cleanup(func() { _ = clientTCP.Close(); _ = serverTCP.Close() })
	return clientTCP, serverTCP
}

func TestV1QuickAckUnderlyingTCPUnwrapsFragmenter(t *testing.T) {
	clientTCP, _ := newTCPConnPair(t)
	fragmenter := NewFragmenter(clientTCP, true)
	tr := &h2Transport{tlsConn: quickAckNetConner{Conn: fragmenter, underlying: fragmenter}}
	if got := tr.underlyingTCPConn(); got != clientTCP {
		t.Fatalf("underlyingTCPConn through Fragmenter = %p, want %p", got, clientTCP)
	}
}

func TestV1ApplyTCPQuickAckFlipUsesUnderlyingSocket(t *testing.T) {
	clientTCP, _ := newTCPConnPair(t)
	fragmenter := NewFragmenter(clientTCP, true)
	tr := &h2Transport{tlsConn: quickAckNetConner{Conn: fragmenter, underlying: fragmenter}}

	oldHook := setClientTCPQuickAck
	var calls atomic.Int32
	var sawQuick atomic.Bool
	var sawTCP atomic.Bool
	setClientTCPQuickAck = func(conn net.Conn, quick bool) error {
		calls.Add(1)
		if conn == clientTCP {
			sawTCP.Store(true)
		}
		if quick {
			sawQuick.Store(true)
		}
		return nil
	}
	t.Cleanup(func() { setClientTCPQuickAck = oldHook })

	tr.applyTCPQuickAckFlip(true)
	if calls.Load() != 1 || !sawTCP.Load() || !sawQuick.Load() {
		t.Fatalf("quickack hook calls=%d sawTCP=%v sawQuick=%v, want one call on underlying TCP with quick=true", calls.Load(), sawTCP.Load(), sawQuick.Load())
	}
}

func TestV1SetTCPQuickAckOnLiveTCPConnSucceeds(t *testing.T) {
	clientTCP, _ := newTCPConnPair(t)
	if err := setTCPQuickAck(clientTCP, true); err != nil {
		t.Fatalf("setTCPQuickAck(true) on live TCPConn: %v", err)
	}
	if err := setTCPQuickAck(clientTCP, false); err != nil {
		t.Fatalf("setTCPQuickAck(false) on live TCPConn: %v", err)
	}
}
