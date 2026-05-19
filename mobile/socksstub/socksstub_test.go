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
		// Legacy format
		{"samizdat://h:18447/?sni=ok&pubkey=" + strings.Repeat("a", 64) + "&shortid=" + strings.Repeat("b", 16) + "&fp=chrome", ""},
		{"samizdat://h:18447/?sni=ok&pubkey=tooshort&shortid=" + strings.Repeat("b", 16), "pubkey"},
		{"samizdat://h:18447/?pubkey=" + strings.Repeat("a", 64) + "&shortid=" + strings.Repeat("b", 16), "missing sni"},
		{"https://example.com/", "scheme must be tamizdat"},
		{"samizdat:///?sni=ok", "missing host"},

		// IPA-M: xray-style format (userinfo + pbk=).
		{"samizdat://" + strings.Repeat("b", 16) + "@h:777?pbk=" + strings.Repeat("a", 64) + "&sni=ok&fp=chrome", ""},
		// xray + #fragment label is ignored.
		{"samizdat://" + strings.Repeat("b", 16) + "@h:777?pbk=" + strings.Repeat("a", 64) + "&sni=ok#llm2", ""},
		// xray pubkey alias public-key-hex= (older).
		{"samizdat://" + strings.Repeat("b", 16) + "@h:777?public-key-hex=" + strings.Repeat("a", 64) + "&sni=ok", ""},
		// userinfo with comma-separated shortIDs (rotation pool).
		{"samizdat://" + strings.Repeat("b", 16) + "," + strings.Repeat("c", 16) + "@h:777?pbk=" + strings.Repeat("a", 64) + "&sni=ok", ""},
		// snipool= multi-SNI rotation pool.
		{"samizdat://" + strings.Repeat("b", 16) + "@h:777?pbk=" + strings.Repeat("a", 64) + "&snipool=ok.ru,vk.com,mail.ru", ""},
		// xray with userinfo OVERRIDING shortid= query (xray priority).
		{"samizdat://" + strings.Repeat("b", 16) + "@h:777?pbk=" + strings.Repeat("a", 64) + "&sni=ok&shortid=" + strings.Repeat("c", 16), ""},
		// userinfo too-short -> error.
		{"samizdat://shortie@h:777?pbk=" + strings.Repeat("a", 64) + "&sni=ok", "shortid must be 16 hex chars"},
		// neither pbk nor pubkey -> error.
		{"samizdat://" + strings.Repeat("b", 16) + "@h:777?sni=ok", "pubkey must be 64 hex chars"},

		// IPA-N (URI scheme v2): v1-only tuning keys (mintr/cap/cover/cpool/
		// tcpfrag/recfrag/idle/conn/drain/mstreams) are silently ignored.
		// Forward-compat: parser accepts any unknown query key without error.
		{"samizdat://" + strings.Repeat("b", 16) + "@h:777?pbk=" + strings.Repeat("a", 64) + "&sni=ok&mintr=2&cap=13312&cover=1&cpool=ok.ru,vk.com&tcpfrag=1&recfrag=1&idle=300000&conn=15000&drain=10000&mstreams=100&future_unknown_key=hello", ""},

		// IPA-R (project rename samizdat -> tamizdat): both schemes accepted.
		{"tamizdat://" + strings.Repeat("b", 16) + "@h:777?pbk=" + strings.Repeat("a", 64) + "&sni=ok", ""},
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

// TestSamizdatXrayPoolFields verifies the SNI / shortID rotation pool
// fields are populated correctly when the URL specifies them (snipool=,
// userinfo with commas).
func TestSamizdatXrayPoolFields(t *testing.T) {
	rt = &runtimeState{logsMax: 100}
	pub := strings.Repeat("a", 64)
	a := strings.Repeat("b", 16)
	b := strings.Repeat("c", 16)
	c := strings.Repeat("d", 16)

	t.Run("xray with snipool + multi-shortID", func(t *testing.T) {
		blob := "samizdat://" + a + "," + b + "," + c + "@h:777?pbk=" + pub +
			"&snipool=ok.ru,vk.com,mail.ru&fp=chrome#llm2"
		cfg, err := parseSamizdatURL(blob)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.ServerHost != "h" || cfg.ServerPort != 777 {
			t.Errorf("server: got %s:%d", cfg.ServerHost, cfg.ServerPort)
		}
		if cfg.SNI != "ok.ru" {
			t.Errorf("primary SNI = %q, want ok.ru", cfg.SNI)
		}
		if got, want := cfg.SNIPool, []string{"ok.ru", "vk.com", "mail.ru"}; len(got) != len(want) {
			t.Errorf("SNIPool len = %d, want %d", len(got), len(want))
		}
		if cfg.ShortIDHex != a {
			t.Errorf("primary shortID = %q, want %q", cfg.ShortIDHex, a)
		}
		if got, want := cfg.ShortIDsHex, []string{a, b, c}; len(got) != len(want) {
			t.Errorf("ShortIDsHex len = %d, want %d", len(got), len(want))
		}
	})

	t.Run("legacy single sni single shortid", func(t *testing.T) {
		blob := "samizdat://h:18447/?sni=ok.ru&pubkey=" + pub + "&shortid=" + a + "&fp=chrome"
		cfg, err := parseSamizdatURL(blob)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.SNI != "ok.ru" {
			t.Errorf("SNI = %q", cfg.SNI)
		}
		if len(cfg.SNIPool) != 0 {
			t.Errorf("SNIPool should be empty, got %v", cfg.SNIPool)
		}
		if len(cfg.ShortIDsHex) != 1 || cfg.ShortIDsHex[0] != a {
			t.Errorf("ShortIDsHex = %v, want [%q]", cfg.ShortIDsHex, a)
		}
	})
}

func TestFragPoCConfigParse(t *testing.T) {
	rt = &runtimeState{logsMax: 100}
	sid := strings.Repeat("a", 16)

	t.Run("userinfo secure ports", func(t *testing.T) {
		cfg, err := parseFragPoCURL("fragpoc://" + sid + "@ai-archive.ru:443?secure=1&ports=443,80")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.ServerHost != "ai-archive.ru" || cfg.ServerPort != 443 {
			t.Fatalf("server = %s:%d", cfg.ServerHost, cfg.ServerPort)
		}
		if !cfg.Secure {
			t.Fatalf("secure = false, want true")
		}
		if got, want := cfg.Ports, []int{443, 80}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("ports = %v, want %v", got, want)
		}
	})

	t.Run("query shortid defaults", func(t *testing.T) {
		cfg, err := parseFragPoCURL("fragpoc://edge.example:8443?shortid=" + sid + "&secure=false")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.Secure {
			t.Fatalf("secure = true, want false")
		}
		if len(cfg.Ports) != 0 {
			t.Fatalf("ports = %v, want empty before runtime default", cfg.Ports)
		}
	})

	for _, tc := range []struct {
		blob string
		want string
	}{
		{"tamizdat://" + sid + "@h:443", "scheme must be fragpoc"},
		{"fragpoc://h:443", "missing shortid"},
		{"fragpoc://short@h:443", "shortid must be 16"},
		{"fragpoc://" + sid + "@h:bad", "invalid port"},
	} {
		if _, err := parseFragPoCURL(tc.blob); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("parse(%q) err=%v, want substring %q", tc.blob, err, tc.want)
		}
	}
}

func TestFragPoCRuntimeConfigUsesCustomURI(t *testing.T) {
	rt = &runtimeState{logsMax: 100}
	sid := strings.Repeat("b", 16)
	SetFragPoCConfig("fragpoc://" + sid + "@ai-archive.ru:443?secure=1&ports=443,80")
	cfg, err := currentFragPoCServerConfig()
	if err != nil {
		t.Fatalf("current config: %v", err)
	}
	if cfg.ServerHost != "ai-archive.ru" || cfg.ServerPort != 443 {
		t.Fatalf("server = %s:%d", cfg.ServerHost, cfg.ServerPort)
	}
	if got, want := cfg.Ports, []int{443, 80}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ports = %v, want %v", got, want)
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
// TestFwdUDPDirectEcho exercises the cmd=0x05 (HEV_SOCKS5_REQ_CMD_FWD_UDP)
// path end-to-end with a localhost UDP echo upstream and direct-dial
// (no samizdat). Verifies framing on both directions: client → upstream
// and reverse.
func TestFwdUDPDirectEcho(t *testing.T) {
	rt = &runtimeState{logsMax: 100}

	// UDP echo server.
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	udpEcho, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("UDP listen: %v", err)
	}
	defer udpEcho.Close()
	echoPort := udpEcho.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 2048)
		for {
			_ = udpEcho.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, peer, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(buf[:n], peer)
		}
	}()

	port := pickPort(t)
	socksAddr := "127.0.0.1:" + strconv.Itoa(port)
	if err := Start(socksAddr); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop()
	if err := SetSamizdatConfig(""); err != nil {
		t.Fatalf("SetSamizdatConfig: %v", err)
	}

	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// SOCKS5 greeting.
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("greeting resp: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greeting reply = %v", resp)
	}

	// Request: VER=05 CMD=05 (FWD_UDP) RSV=00 ATYP=01 ADDR=0.0.0.0 PORT=0.
	req := []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("FWD_UDP req: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("FWD_UDP reply = %v, want 05 00 (success)", reply)
	}

	// Send one framed datagram to 127.0.0.1:echoPort.
	payload := []byte("ping-ping")
	addrSection := []byte{0x01, 127, 0, 0, 1} // atyp + ipv4
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(echoPort))
	addrSection = append(addrSection, portBytes...)
	// addrSection now: atyp(1) + ipv4(4) + port(2) = 7 bytes
	hdrLen := 3 + len(addrSection) // 10
	frame := make([]byte, 0, hdrLen+len(payload))
	dlen := make([]byte, 2)
	binary.BigEndian.PutUint16(dlen, uint16(len(payload)))
	frame = append(frame, dlen...)
	frame = append(frame, byte(hdrLen))
	frame = append(frame, addrSection...)
	frame = append(frame, payload...)
	if _, err := c.Write(frame); err != nil {
		t.Fatalf("write framed datagram: %v", err)
	}

	// Read echo back framed the same way.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 3)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read reverse hdr: %v", err)
	}
	rdLen := binary.BigEndian.Uint16(hdr[0:2])
	rhdrLen := int(hdr[2])
	if rhdrLen != hdrLen {
		t.Fatalf("reverse hdrLen = %d, want %d", rhdrLen, hdrLen)
	}
	if int(rdLen) != len(payload) {
		t.Fatalf("reverse datLen = %d, want %d", rdLen, len(payload))
	}
	rest := make([]byte, rhdrLen-3+int(rdLen))
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("read reverse rest: %v", err)
	}
	gotData := rest[rhdrLen-3:]
	if !bytesEqual(gotData, payload) {
		t.Fatalf("reverse data = %q, want %q", gotData, payload)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDialUpstreamNilContextDoesNotCrash(t *testing.T) {
	rt = &runtimeState{logsMax: 50}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _ = dialUpstream(ctx, "127.0.0.1:1") // port 1 should be ECONNREFUSED, not crash
}
