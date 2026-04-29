// Package socksstub is the gomobile-bound entry point for the main-app-side
// SOCKS5 listener that the Path 3 architecture uses. The hev-socks5-tunnel
// instance running inside the iOS extension forwards every TCP/UDP flow to
// this listener; the extension never speaks the proxy protocol itself, so
// it stays well under iOS's NEPacketTunnelProvider memory cap.
//
// Two operating modes:
//
//   - Stub mode: direct dial. The listener accepts SOCKS5 CONNECT requests
//     and dials the upstream destination directly. Useful for POC testing
//     of the architecture (proves the IPC + lifecycle work end-to-end)
//     without depending on samizdat.
//
//   - Samizdat mode: forward via Client.DialContext / Client.DialUDP.
//     This is the production path. Activated by SetSamizdatConfig with
//     a samizdat:// URL.
//
// Public gomobile API:
//
//   func Start(socketPath string) error
//   func Stop()
//   func Status() string                       // "stopped" | "listening"
//   func ConnectionsCount() int
//   func SetSamizdatConfig(blob string) error  // empty string → direct dial
//   func Logs() string
package socksstub

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	socksVersion5      = 0x05
	socksMethodNoAuth  = 0x00
	socksCmdConnect    = 0x01
	socksAtypIPv4      = 0x01
	socksAtypDomain    = 0x03
	socksAtypIPv6      = 0x04
	socksReplySuccess  = 0x00
	socksReplyHostUnk  = 0x04
	socksReplyConnRef  = 0x05
	socksReplyCmdNoSup = 0x07
	socksReplyAtypNo   = 0x08
)

type runtimeState struct {
	mu          sync.Mutex
	listener    net.Listener
	cancel      context.CancelFunc
	ctx         context.Context
	socketPath  string
	logs        []string
	logsMax     int
	samizdat    string // empty → direct dial mode
	connsActive atomic.Int64
	connsTotal  atomic.Uint64
}

var rt = &runtimeState{logsMax: 500}

// Log file mirror — same App Group file the extension writes to. The
// main-app side calls SetLogSink at startup so SocksStub heartbeats
// appear in the same unified log the user sees in the LogView.
var (
	logSinkMu sync.Mutex
	logSink   *os.File
)

// SetLogSink opens the given path in append mode (creating if necessary).
// Pass an empty string to detach.
func SetLogSink(path string) {
	if path == "" {
		logSinkMu.Lock()
		if logSink != nil {
			logSink.Close()
			logSink = nil
		}
		logSinkMu.Unlock()
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	logSinkMu.Lock()
	if logSink != nil {
		logSink.Close()
	}
	logSink = f
	logSinkMu.Unlock()
}

// Start opens a SOCKS5 listener.
//
//   - addrSpec starting with "/" or "unix:" → UNIX domain socket. Used
//     when the consumer also lives in the same App Group container.
//   - otherwise treated as a TCP "host:port". hev-socks5-tunnel doesn't
//     parse UNIX sockets in its config, so the actual Path 3 ext-to-app
//     bridge uses TCP on 127.0.0.1 with a fixed port.
//
// Idempotent — calling again with a different addr is a no-op (Stop
// first). Returns immediately; the accept loop runs in the background.
func Start(addrSpec string) error {
	rt.mu.Lock()
	if rt.listener != nil {
		rt.mu.Unlock()
		return errors.New("already listening")
	}
	rt.mu.Unlock()

	network := "tcp"
	addr := addrSpec
	if len(addrSpec) > 0 && (addrSpec[0] == '/' || (len(addrSpec) > 5 && addrSpec[:5] == "unix:")) {
		network = "unix"
		if addrSpec[0] != '/' {
			addr = addrSpec[5:]
		}
		_ = os.Remove(addr)
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", network, addr, err)
	}
	if network == "unix" {
		_ = os.Chmod(addr, 0o600)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt.mu.Lock()
	rt.listener = ln
	rt.ctx = ctx
	rt.cancel = cancel
	rt.socketPath = addr
	rt.mu.Unlock()

	rt.appendLog(fmt.Sprintf("info: socks listener up on %s://%s", network, addr))
	go acceptLoop(ctx, ln)
	return nil
}

// Stop closes the listener and any active connections.
func Stop() {
	rt.mu.Lock()
	ln := rt.listener
	cancel := rt.cancel
	path := rt.socketPath
	rt.listener = nil
	rt.cancel = nil
	rt.ctx = nil
	rt.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	// Remove only if it looks like a UDS path (TCP "127.0.0.1:1080"
	// would not be a valid path).
	if path != "" && len(path) > 0 && path[0] == '/' {
		_ = os.Remove(path)
	}
	rt.appendLog("info: socks listener stopped")
}

// Status returns "stopped" or "listening".
func Status() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.listener == nil {
		return "stopped"
	}
	return "listening"
}

// ConnectionsActive returns the number of currently-open client conns.
func ConnectionsActive() int {
	return int(rt.connsActive.Load())
}

// ConnectionsTotal returns the running total of connections accepted
// since the listener started (does not reset on stop).
func ConnectionsTotal() int64 {
	return int64(rt.connsTotal.Load())
}

// SetSamizdatConfig switches the listener between direct-dial mode (empty
// string) and samizdat mode (samizdat:// URL). The next accepted SOCKS5
// connection will use the new mode.
//
// POC stage 1 of Path 3 uses empty string only — direct dial — and
// validates that the architecture survives the iOS extension memory wall.
// Stage 2 will swap in the samizdat client implementation.
func SetSamizdatConfig(blob string) error {
	// Stage 1 placeholder: only direct mode is supported. We accept the
	// call to keep the gomobile API stable so the app can call it without
	// caring which stage we're at.
	rt.mu.Lock()
	rt.samizdat = blob
	rt.mu.Unlock()
	if blob == "" {
		rt.appendLog("info: dial mode = direct")
	} else {
		rt.appendLog("warn: samizdat mode requested but not yet wired (POC stage 1 = direct)")
	}
	return nil
}

// Logs returns the recent in-memory log buffer joined with newlines.
func Logs() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.logs) == 0 {
		return ""
	}
	out := make([]byte, 0, 80*len(rt.logs))
	for i, l := range rt.logs {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, l...)
	}
	return string(out)
}

func (r *runtimeState) appendLog(line string) {
	stamp := time.Now().Format("15:04:05.000")
	full := stamp + " app/socks: " + line
	r.mu.Lock()
	r.logs = append(r.logs, full)
	if len(r.logs) > r.logsMax {
		drop := len(r.logs) - r.logsMax
		r.logs = append(r.logs[:0], r.logs[drop:]...)
	}
	r.mu.Unlock()

	logSinkMu.Lock()
	sink := logSink
	logSinkMu.Unlock()
	if sink != nil {
		_, _ = sink.WriteString(full + "\n")
	}
}

// acceptLoop services incoming SOCKS5 client connections.
func acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rt.appendLog(fmt.Sprintf("warn: accept: %v", err))
			return
		}
		rt.connsActive.Add(1)
		rt.connsTotal.Add(1)
		go func(client net.Conn) {
			defer client.Close()
			defer rt.connsActive.Add(-1)
			handleSocks(ctx, client)
		}(c)
	}
}

func handleSocks(ctx context.Context, client net.Conn) {
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Greeting: VER NMETHODS METHODS{n}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != socksVersion5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	// Always answer "no auth".
	if _, err := client.Write([]byte{socksVersion5, socksMethodNoAuth}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[0] != socksVersion5 {
		return
	}
	if req[1] != socksCmdConnect {
		_ = sendReply(client, socksReplyCmdNoSup)
		return
	}

	var host string
	switch req[3] {
	case socksAtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(client, buf); err != nil {
			return
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	case socksAtypDomain:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(client, ln); err != nil {
			return
		}
		buf := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(client, buf); err != nil {
			return
		}
		host = string(buf)
	case socksAtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(client, buf); err != nil {
			return
		}
		host = "[" + net.IP(buf).String() + "]"
	default:
		_ = sendReply(client, socksReplyAtypNo)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	dest := net.JoinHostPort(host, strconv.Itoa(int(port)))

	_ = client.SetReadDeadline(time.Time{})

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	upstream, err := dialUpstream(dialCtx, dest)
	cancel()
	if err != nil {
		// Map common errors to SOCKS reply codes for client benefit.
		code := byte(socksReplyHostUnk)
		var oerr *net.OpError
		if errors.As(err, &oerr) && oerr.Err != nil {
			if oerr.Err.Error() == "connection refused" {
				code = socksReplyConnRef
			}
		}
		_ = sendReply(client, code)
		return
	}
	defer upstream.Close()

	if err := sendReply(client, socksReplySuccess); err != nil {
		return
	}

	relay(client, upstream)
}

func sendReply(client net.Conn, code byte) error {
	// Standard 10-byte reply: bound addr 0.0.0.0:0, atyp ipv4.
	reply := []byte{socksVersion5, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := client.Write(reply)
	return err
}

// dialUpstream is the swap-point: stage 1 = direct, stage 2 = samizdat.
func dialUpstream(ctx context.Context, dest string) (net.Conn, error) {
	rt.mu.Lock()
	mode := rt.samizdat
	rt.mu.Unlock()
	if mode == "" {
		// Direct dial. iOS allows TCP outbound from a foreground app.
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dest)
	}
	// TODO(stage 2): samizdat client.DialContext(ctx, "tcp", dest)
	// For now, fall through to direct so partial config doesn't break.
	rt.appendLog("warn: samizdat mode set but not yet wired; using direct")
	var d net.Dialer
	return d.DialContext(ctx, "tcp", dest)
}

// relay copies bytes between two duplex streams until either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(b, a, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(a, b, buf)
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
}
