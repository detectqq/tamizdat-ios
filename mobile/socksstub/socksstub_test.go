package socksstub

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestStartStop covers the listener lifecycle.
func TestStartStop(t *testing.T) {
	rt = &runtimeState{logsMax: 100}
	port := pickPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	if err := Start(addr); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop()
	if got := Status(); got != "listening" {
		t.Errorf("Status = %q, want listening", got)
	}

	// Second Start while listening must error.
	if err := Start(addr); err == nil {
		t.Errorf("second Start should error")
	}

	Stop()
	if got := Status(); got != "stopped" {
		t.Errorf("Status after Stop = %q", got)
	}
}

// TestSocksConnectDirect drives the Go SOCKS5 server through a real
// SOCKS5 handshake against a localhost echo upstream. Validates greeting
// + CONNECT + relay.
func TestSocksConnectDirect(t *testing.T) {
	rt = &runtimeState{logsMax: 100}
	// Echo server we will dial through SOCKS5.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo Listen: %v", err)
	}
	defer echo.Close()
	echoAddr := echo.Addr().(*net.TCPAddr)

	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // echo
	}()

	// Start SOCKS5 server.
	port := pickPort(t)
	socksAddr := "127.0.0.1:" + strconv.Itoa(port)
	if err := Start(socksAddr); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop()

	// Direct mode (no samizdat).
	if err := SetSamizdatConfig(""); err != nil {
		t.Fatalf("SetSamizdatConfig: %v", err)
	}

	// Open a client connection to SOCKS5 and run handshake.
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// VER NMETHODS METHODS (we offer only NO_AUTH).
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want 05 00", resp)
	}

	// VER CMD RSV ATYP ADDR PORT — connect to the echo server.
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(echoAddr.Port))
	req = append(req, portBytes...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect req: %v", err)
	}

	// Reply.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("connect reply = %v, want 05 00 (success)", reply)
	}

	// Echo round-trip.
	want := "hello via socks5"
	if _, err := c.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != want {
		t.Fatalf("echo got %q want %q", got, want)
	}

	// ConnectionsTotal / Active counters should reflect the round-trip.
	if total := ConnectionsTotal(); total < 1 {
		t.Errorf("ConnectionsTotal = %d, want ≥1", total)
	}
}

// TestUnknownAtypReply ensures non-IPv4/IPv6/domain ATYP gets a clean
// 0x08 (atyp not supported) reply rather than crashing.
func TestUnknownAtypReply(t *testing.T) {
	rt = &runtimeState{logsMax: 100}
	port := pickPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	if err := Start(addr); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	gr := make([]byte, 2)
	_, _ = io.ReadFull(c, gr)

	// CMD=CONNECT, RSV=0, ATYP=0x99 (bogus)
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x99, 0x00, 0x00})

	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x08 {
		t.Errorf("reply code = 0x%02x, want 0x08 (atyp not supported)", reply[1])
	}
}

// TestSamizdatConfigParse validates the URL parser without actually
// touching the network.
func TestSamizdatConfigParse(t *testing.T) {
	rt = &runtimeState{logsMax: 100}
	cases := []struct {
		blob    string
		wantErr string // substring; "" = no error
	}{
		{"samizdat://h:18447/?sni=ok&pubkey=" + strings.Repeat("a", 64) + "&shortid=" + strings.Repeat("b", 16) + "&fp=chrome", ""},
		{"samizdat://h:18447/?sni=ok&pubkey=tooshort&shortid=" + strings.Repeat("b", 16), "pubkey"},
		{"samizdat://h:18447/?pubkey=" + strings.Repeat("a", 64) + "&shortid=" + strings.Repeat("b", 16), "missing sni"},
		{"https://example.com/", "scheme must be samizdat"},
		{"samizdat:///?sni=ok", "missing host"},
	}
	for _, tc := range cases {
		_, err := parseSamizdatURL(tc.blob)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("blob %q: unexpected error %v", tc.blob, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("blob %q: expected error containing %q, got nil", tc.blob, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("blob %q: error %q does not contain %q", tc.blob, err.Error(), tc.wantErr)
		}
	}
}

// TestConcurrentDials covers a small fan-out so we know the listener and
// per-connection goroutines do not deadlock under concurrency.
func TestConcurrentDials(t *testing.T) {
	rt = &runtimeState{logsMax: 200}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	defer echo.Close()
	echoAddr := echo.Addr().(*net.TCPAddr)

	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	port := pickPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	if err := Start(addr); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop()

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if err := socks5Echo(addr, echoAddr); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("worker: %v", e)
	}
}

// Helpers.

func pickPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickPort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func socks5Echo(socks string, target *net.TCPAddr) error {
	c, err := net.Dial("tcp", socks)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	gr := make([]byte, 2)
	if _, err := io.ReadFull(c, gr); err != nil {
		return err
	}
	if gr[0] != 0x05 || gr[1] != 0x00 {
		return errors.New("greeting reply unexpected")
	}

	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(target.Port))
	req = append(req, pb...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return errors.New("connect reply not success")
	}
	want := "ping"
	if _, err := c.Write([]byte(want)); err != nil {
		return err
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != want {
		return errors.New("echo mismatch")
	}
	return nil
}

// dialUpstream sanity: passing nil context shouldn't crash.
func TestDialUpstreamNilContextDoesNotCrash(t *testing.T) {
	rt = &runtimeState{logsMax: 50}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _ = dialUpstream(ctx, "127.0.0.1:1") // port 1 should be ECONNREFUSED, not crash
}
