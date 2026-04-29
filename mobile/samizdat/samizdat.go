// Package samizdat exposes a gomobile-friendly API for the iOS app and
// PacketTunnelProvider extension.
package samizdat

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	core "github.com/getlantern/samizdat"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateError        = "error"
)

type config struct {
	ServerHost       string
	ServerPort       int
	SNI              string
	PubkeyHex        string
	ShortIDHex       string
	Fingerprint      string
	TCPFragmentation bool
}

type runtimeState struct {
	mu        sync.Mutex
	state     string
	lastErr   string
	cfg       *config
	logs      []string
	logsMax   int
	cancelCh  chan struct{}
	socksAddr string
	tunnel    *packetTunnel
}

var rt = &runtimeState{
	state:   StateDisconnected,
	logsMax: 1000,
}

// Connect is kept for the main app's lightweight smoke path. The real
// full-device VPN path runs in PacketTunnelProvider via TunnelStart.
func Connect(configBlob string) error {
	cfg, err := parseConfig(configBlob)
	if err != nil {
		rt.setError("parse: " + err.Error())
		return err
	}

	rt.mu.Lock()
	if rt.state == StateConnecting || rt.state == StateConnected {
		rt.mu.Unlock()
		return errors.New("already connecting or connected; call Disconnect first")
	}
	rt.state = StateConnected
	rt.lastErr = ""
	rt.cfg = cfg
	rt.socksAddr = ""
	rt.mu.Unlock()

	rt.appendLog(fmt.Sprintf("info: config ok for %s:%d; VPN engine runs in PacketTunnelProvider", cfg.ServerHost, cfg.ServerPort))
	return nil
}

func Disconnect() {
	TunnelStop()
	rt.mu.Lock()
	if rt.cancelCh != nil {
		close(rt.cancelCh)
		rt.cancelCh = nil
	}
	rt.state = StateDisconnected
	rt.socksAddr = ""
	rt.mu.Unlock()
	rt.appendLog("info: disconnected")
}

func Status() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.state
}

func LastError() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.lastErr
}

func SocksAddr() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.socksAddr
}

func Logs(n int) string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if n <= 0 || n > len(rt.logs) {
		n = len(rt.logs)
	}
	if n == 0 {
		return ""
	}
	start := len(rt.logs) - n
	out := ""
	for i, l := range rt.logs[start:] {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}

func ClearLogs() {
	rt.mu.Lock()
	rt.logs = rt.logs[:0]
	rt.mu.Unlock()
}

func ParseConfigError(configBlob string) string {
	if _, err := parseConfig(configBlob); err != nil {
		return err.Error()
	}
	return ""
}

func Version() string {
	return "0.2.0-vpn"
}

func AddLog(line string) {
	rt.appendLog(line)
}

// TunnelStart starts the gVisor TCP/IP stack used by the iOS Packet Tunnel
// extension. Swift injects raw IP packets with TunnelInjectPacket and drains
// outgoing packets via TunnelReadPacket.
func TunnelStart(configBlob string) error {
	cfg, err := parseConfig(configBlob)
	if err != nil {
		rt.setError("parse: " + err.Error())
		return err
	}

	rt.mu.Lock()
	if rt.tunnel != nil {
		rt.mu.Unlock()
		return errors.New("tunnel already running")
	}
	rt.state = StateConnecting
	rt.lastErr = ""
	rt.cfg = cfg
	rt.mu.Unlock()

	tun, err := newPacketTunnel(cfg)
	if err != nil {
		rt.setError(err.Error())
		return err
	}

	rt.mu.Lock()
	rt.tunnel = tun
	rt.state = StateConnected
	rt.mu.Unlock()
	rt.appendLog(fmt.Sprintf("info: packet tunnel active via %s:%d", cfg.ServerHost, cfg.ServerPort))
	return nil
}

func TunnelStop() {
	rt.mu.Lock()
	tun := rt.tunnel
	rt.tunnel = nil
	rt.state = StateDisconnected
	rt.mu.Unlock()
	if tun != nil {
		tun.Close()
		rt.appendLog("info: packet tunnel stopped")
	}
}

func TunnelInjectPacket(packet []byte) error {
	rt.mu.Lock()
	tun := rt.tunnel
	rt.mu.Unlock()
	if tun == nil {
		return errors.New("tunnel not running")
	}
	return tun.InjectPacket(packet)
}

func TunnelReadPacket() []byte {
	rt.mu.Lock()
	tun := rt.tunnel
	rt.mu.Unlock()
	if tun == nil {
		return nil
	}
	return tun.ReadPacket()
}

type packetTunnel struct {
	ctx    context.Context
	cancel context.CancelFunc
	client *core.Client
	ep     *packetFlowEndpoint
	stack  *stack.Stack
}

func newPacketTunnel(cfg *config) (*packetTunnel, error) {
	pubKeyBytes, err := hex.DecodeString(cfg.PubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey: %w", err)
	}
	shortIDBytes, err := hex.DecodeString(cfg.ShortIDHex)
	if err != nil {
		return nil, fmt.Errorf("invalid shortid: %w", err)
	}
	if len(shortIDBytes) != 8 {
		return nil, fmt.Errorf("shortid must be 8 bytes, got %d", len(shortIDBytes))
	}
	var shortID [8]byte
	copy(shortID[:], shortIDBytes)

	// Match the production server's defaults: BBCR on, both fragmenters on,
	// noise frames on. We let the upstream applyDefaults() fill timeouts /
	// pool sizes / churn rates by leaving them zero.
	client, err := core.NewClient(core.ClientConfig{
		ServerAddr:  net.JoinHostPort(cfg.ServerHost, strconv.Itoa(cfg.ServerPort)),
		ServerName:  cfg.SNI,
		PublicKey:   pubKeyBytes,
		ShortID:     shortID,
		Fingerprint: cfg.Fingerprint,
		// EnableBBCR=nil → upstream defaults to true.
		// TCPFragmentation/RecordFragmentation/NoiseFrames default to true.
	})
	if err != nil {
		return nil, fmt.Errorf("creating samizdat client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ep := newPacketFlowEndpoint(1500, 4096)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	tun := &packetTunnel{
		ctx:    ctx,
		cancel: cancel,
		client: client,
		ep:     ep,
		stack:  s,
	}

	nicID := tcpip.NICID(1)
	if tcpErr := s.CreateNIC(nicID, ep); tcpErr != nil {
		tun.Close()
		return nil, fmt.Errorf("CreateNIC: %v", tcpErr)
	}
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	recvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     65536,
		Default: 1048576,
		Max:     16 * 1024 * 1024,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &recvOpt)
	sendOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     65536,
		Default: 1048576,
		Max:     16 * 1024 * 1024,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendOpt)
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	tcpFwd := tcp.NewForwarder(s, 1048576, 65535, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dest := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		var wq waiter.Queue
		endpoint, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			rt.appendLog(fmt.Sprintf("error: TCP CreateEndpoint: %v", tcpErr))
			r.Complete(true)
			return
		}
		r.Complete(false)
		localConn := gonet.NewTCPConn(&wq, endpoint)
		go func() {
			defer localConn.Close()
			remote, dialErr := client.DialContext(ctx, "tcp", dest)
			if dialErr != nil {
				rt.appendLog(fmt.Sprintf("error: TCP dial %s: %v", dest, dialErr))
				return
			}
			defer remote.Close()
			relay(localConn, remote)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP forwarder: Phase B server now supports UDP-over-CONNECT
	// (Client.DialUDP), so we proxy ALL UDP. DNS uses a short-lived path
	// since iOS resolvers send one-shot 4096-byte queries; non-DNS UDP
	// (QUIC, WireGuard, games) gets a long-lived bidirectional pump.
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		dest := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		var wq waiter.Queue
		endpoint, udpErr := r.CreateEndpoint(&wq)
		if udpErr != nil {
			rt.appendLog(fmt.Sprintf("error: UDP CreateEndpoint %s: %v", dest, udpErr))
			return true
		}
		conn := gonet.NewUDPConn(&wq, endpoint)
		go func() {
			defer conn.Close()
			forwardUDP(ctx, conn, dest, client)
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return tun, nil
}

func (t *packetTunnel) InjectPacket(packet []byte) error {
	return t.ep.InjectPacket(packet)
}

func (t *packetTunnel) ReadPacket() []byte {
	select {
	case pkt := <-t.ep.outbound:
		return pkt
	case <-t.ctx.Done():
		return nil
	case <-t.ep.closed:
		return nil
	}
}

func (t *packetTunnel) Close() {
	t.cancel()
	t.ep.Close()
	t.stack.Close()
	t.client.Close()
}

type packetFlowEndpoint struct {
	mtu        uint32
	dispatcher stack.NetworkDispatcher
	outbound   chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
}

func newPacketFlowEndpoint(mtu uint32, queueDepth int) *packetFlowEndpoint {
	return &packetFlowEndpoint{
		mtu:      mtu,
		outbound: make(chan []byte, queueDepth),
		closed:   make(chan struct{}),
	}
}

func (e *packetFlowEndpoint) MTU() uint32                                  { return e.mtu }
func (e *packetFlowEndpoint) SetMTU(mtu uint32)                            { e.mtu = mtu }
func (e *packetFlowEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *packetFlowEndpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *packetFlowEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *packetFlowEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }
func (e *packetFlowEndpoint) IsAttached() bool                             { return e.dispatcher != nil }
func (e *packetFlowEndpoint) Wait()                                        {}
func (e *packetFlowEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *packetFlowEndpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *packetFlowEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *packetFlowEndpoint) SetOnCloseAction(func())                      {}
func (e *packetFlowEndpoint) Attach(dispatcher stack.NetworkDispatcher)    { e.dispatcher = dispatcher }

func (e *packetFlowEndpoint) Close() {
	e.closeOnce.Do(func() {
		close(e.closed)
	})
}

func (e *packetFlowEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, pkt := range pkts.AsSlice() {
		view := pkt.ToView()
		data := append([]byte(nil), view.AsSlice()...)
		view.Release()
		select {
		case <-e.closed:
			return n, nil
		case e.outbound <- data:
			n++
		default:
			rt.appendLog("warn: packetFlow outbound queue full; dropping packet")
		}
	}
	return n, nil
}

func (e *packetFlowEndpoint) InjectPacket(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if e.dispatcher == nil {
		return errors.New("packet endpoint is not attached")
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data),
	})
	switch header.IPVersion(data) {
	case 4:
		e.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkt)
	case 6:
		e.dispatcher.DeliverNetworkPacket(header.IPv6ProtocolNumber, pkt)
	default:
		pkt.DecRef()
		return nil
	}
	pkt.DecRef()
	return nil
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 256*1024)
		io.CopyBuffer(b, a, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 256*1024)
		io.CopyBuffer(a, b, buf)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
}

// forwardUDP bridges a single iOS-side gVisor UDP "connection" (one
// (clientIP, clientPort, destIP, destPort) tuple) to a samizdat
// UDP-over-CONNECT stream. Datagrams are length-framed inside an H2
// stream by the upstream samizdat client (see udp_packetconn.go).
//
// Phase B replaced the legacy DNS-over-TCP hack with real UDP, so this
// path also serves DNS (port 53). The previous IPv6 "udp:" prefix bug
// is gone — DialUDP takes a plain "host:port".
func forwardUDP(ctx context.Context, conn *gonet.UDPConn, dest string, client *core.Client) {
	remote, err := client.DialUDP(ctx, dest)
	if err != nil {
		rt.appendLog(fmt.Sprintf("error: UDP dial %s: %v", dest, err))
		return
	}
	defer remote.Close()

	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// samizdat's PacketConn is single-target; WriteTo accepts the bound
	// remote unconditionally, but Go's net.Addr interface still demands
	// a value here.
	dummyAddr := &streamAddr{network: "udp", address: dest}

	// Local (gVisor) → remote (samizdat).
	go func() {
		defer cancel()
		buf := make([]byte, 65536)
		for {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if pumpCtx.Err() != nil {
				return
			}
			if _, err := remote.WriteTo(buf[:n], dummyAddr); err != nil {
				return
			}
		}
	}()

	// Remote (samizdat) → local (gVisor).
	go func() {
		defer cancel()
		buf := make([]byte, 65536)
		for {
			remote.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, _, err := remote.ReadFrom(buf)
			if err != nil {
				return
			}
			if pumpCtx.Err() != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	<-pumpCtx.Done()
}

// streamAddr is a minimal net.Addr — samizdat's PacketConn ignores the
// remote address on WriteTo, but Go's interface still requires one.
type streamAddr struct {
	network string
	address string
}

func (a *streamAddr) Network() string { return a.network }
func (a *streamAddr) String() string  { return a.address }

func (r *runtimeState) setState(s string) {
	r.mu.Lock()
	r.state = s
	r.mu.Unlock()
}

func (r *runtimeState) setError(msg string) {
	r.mu.Lock()
	r.state = StateError
	r.lastErr = msg
	r.mu.Unlock()
	r.appendLog("error: " + msg)
}

func (r *runtimeState) appendLog(line string) {
	stamp := time.Now().Format("15:04:05.000")
	full := stamp + " " + line
	r.mu.Lock()
	r.logs = append(r.logs, full)
	if len(r.logs) > r.logsMax {
		drop := len(r.logs) - r.logsMax
		r.logs = append(r.logs[:0], r.logs[drop:]...)
	}
	r.mu.Unlock()
}

func parseConfig(blob string) (*config, error) {
	u, err := url.Parse(blob)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}
	if u.Scheme != "samizdat" {
		return nil, fmt.Errorf("scheme must be samizdat:// (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("missing host")
	}
	portStr := u.Port()
	if portStr == "" {
		return nil, errors.New("missing port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	q := u.Query()
	if connectHost := q.Get("connect_host"); connectHost != "" {
		host = connectHost
	}
	if connectPort := q.Get("connect_port"); connectPort != "" {
		parsedPort, err := strconv.Atoi(connectPort)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			return nil, fmt.Errorf("invalid connect_port %q", connectPort)
		}
		port = parsedPort
	}

	sni := q.Get("sni")
	if sni == "" {
		return nil, errors.New("missing ?sni=")
	}
	pub := q.Get("pubkey")
	if len(pub) != 64 || !isHex(pub) {
		return nil, errors.New("pubkey must be 64 hex chars")
	}
	sid := q.Get("shortid")
	if len(sid) != 16 || !isHex(sid) {
		return nil, errors.New("shortid must be 16 hex chars")
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	switch fp {
	case "chrome", "firefox", "safari":
	default:
		return nil, fmt.Errorf("fp must be chrome/firefox/safari (got %q)", fp)
	}

	tcpFrag := true
	if raw := q.Get("tcpfrag"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("tcpfrag must be true/false (got %q)", raw)
		}
		tcpFrag = parsed
	}

	return &config{
		ServerHost:       host,
		ServerPort:       port,
		SNI:              sni,
		PubkeyHex:        pub,
		ShortIDHex:       sid,
		Fingerprint:      fp,
		TCPFragmentation: tcpFrag,
	}, nil
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
