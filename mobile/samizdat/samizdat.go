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
	"runtime"
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

	// Periodic runtime metrics — gives us a memory ceiling history so when
	// iOS kills the NEPacketTunnelProvider extension (50 MB hard cap on
	// recent iOS), we can read the last snapshot before death from the app
	// side via SamizdatLogs.
	go runtimeMetricsLoop(tun.ctx)

	return nil
}

func runtimeMetricsLoop(ctx context.Context) {
	// 2s tick — fast enough to land 4-5 snapshots inside the few seconds
	// between iOS killing the extension and us learning about it through
	// the bridge poll, but slow enough not to spam the buffer.
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			// Sys is the closest go-runtime knob to iOS-visible RSS.
			// Hit ~50 MB and the NEPacketTunnelProvider gets reaped.
			rt.appendLog(fmt.Sprintf(
				"info: rt heap=%dKB sys=%dKB(<50MB cap) goroutines=%d numgc=%d",
				ms.HeapAlloc/1024,
				ms.Sys/1024,
				runtime.NumGoroutine(),
				ms.NumGC,
			))
		}
	}
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

	// MaxStreamsPerConn=1000 instead of upstream default 100. The default
	// is right for desktop SOCKS5 but on iOS a Speedtest spawns 100-300
	// parallel streams in seconds. With cap=100 the connpool spins up a
	// fresh TCP+TLS+H2 every 100 streams, and uTLS Chrome handshakes on
	// arm64 are CPU-expensive — the handshake storm blows the extension's
	// memory budget AND the server starts rejecting new TLS sessions
	// (EOF). One transport carrying 1000 H2 streams is much cheaper.
	client, err := core.NewClient(core.ClientConfig{
		ServerAddr:        net.JoinHostPort(cfg.ServerHost, strconv.Itoa(cfg.ServerPort)),
		ServerName:        cfg.SNI,
		PublicKey:         pubKeyBytes,
		ShortID:           shortID,
		Fingerprint:       cfg.Fingerprint,
		MaxStreamsPerConn: 1000,
		// TCPFragmentation/RecordFragmentation default to true via applyDefaults.
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

	// gVisor TCP buffers — sized for the iOS NEPacketTunnelProvider's
	// 50 MB RSS cap, NOT the desktop server's. Original settings (1 MB
	// default / 16 MB max) blew through the cap inside ~60s of Speedtest:
	// 10-20 parallel streams × 16 MB recv × 16 MB send → easily 300+ MB.
	// Mobile cap of 1 MB max is enough for ~80 Mbps over 10-15 ms RTT
	// (BDP ≈ 100-150 KB) with comfortable headroom; further streams just
	// share the budget instead of stacking it.
	recvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     32 * 1024,
		Default: 128 * 1024,
		Max:     1 * 1024 * 1024,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &recvOpt)
	sendOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     32 * 1024,
		Default: 128 * 1024,
		Max:     1 * 1024 * 1024,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendOpt)
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	// tcp.NewForwarder(stack, recvWindowDefault, maxInFlight, …) — defaults
	// trimmed to match the new buffer ceiling above.
	tcpFwd := tcp.NewForwarder(s, 128*1024, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		host := id.LocalAddress.String()
		dest := net.JoinHostPort(host, strconv.Itoa(int(id.LocalPort)))
		// Drop IPv6 destinations: production samizdat server has no IPv6
		// uplink, so DialContext / DialUDP would just round-trip an HTTP/2
		// CONNECT only to come back with 502 "dial failed". By RST-ing the
		// stream immediately we make iOS apps fall back to IPv4 within
		// 100-300 ms instead of waiting on tunnel timeouts.
		if isIPv6Address(host) {
			noteIPv6Drop("TCP", dest)
			r.Complete(true)
			return
		}
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
			release, ok := acquireDial(ctx)
			if !ok {
				return // dial-cap dropped or ctx canceled
			}
			remote, dialErr := client.DialContext(ctx, "tcp", dest)
			release()
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
		host := id.LocalAddress.String()
		dest := net.JoinHostPort(host, strconv.Itoa(int(id.LocalPort)))
		// Drop IPv6 — see TCP forwarder above for rationale.
		if isIPv6Address(host) {
			noteIPv6Drop("UDP", dest)
			return false
		}
		var wq waiter.Queue
		endpoint, udpErr := r.CreateEndpoint(&wq)
		if udpErr != nil {
			rt.appendLog(fmt.Sprintf("error: UDP CreateEndpoint %s: %v", dest, udpErr))
			return true
		}
		conn := gonet.NewUDPConn(&wq, endpoint)
		isDNS := id.LocalPort == 53
		go func() {
			defer conn.Close()
			if isDNS {
				forwardDNS(ctx, conn, dest, client)
			} else {
				forwardUDP(ctx, conn, dest, client)
			}
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
	// 32 KB matches io.Copy's internal default; 256 KB was wasteful
	// per-stream on the iOS extension (64 streams × 2 dirs × 256 KB =
	// 32 MB just for the relay copy buffers).
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		io.CopyBuffer(b, a, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		io.CopyBuffer(a, b, buf)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
}

// forwardDNS handles UDP/53 with a short-TTL response cache and a
// single round-trip (no long-lived UDP-over-CONNECT — DNS queries are
// one-shot, lingering streams just leak goroutines).
func forwardDNS(ctx context.Context, conn *gonet.UDPConn, dest string, client *core.Client) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	query := buf[:n]

	if cached := dnsCacheGet(query); cached != nil {
		_, _ = conn.Write(cached)
		return
	}

	release, ok := acquireDial(ctx)
	if !ok {
		return
	}
	remote, err := client.DialUDP(ctx, dest)
	release()
	if err != nil {
		rt.appendLog(fmt.Sprintf("error: DNS UDP dial %s: %v", dest, err))
		return
	}
	defer remote.Close()

	dummyAddr := &streamAddr{network: "udp", address: dest}
	if _, err := remote.WriteTo(query, dummyAddr); err != nil {
		return
	}
	if err := remote.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	resp := make([]byte, 4096)
	rn, _, err := remote.ReadFrom(resp)
	if err != nil || rn == 0 {
		return
	}
	dnsCachePut(query, resp[:rn])
	_, _ = conn.Write(resp[:rn])
}

// forwardUDP bridges a single iOS-side gVisor UDP "connection" (one
// (clientIP, clientPort, destIP, destPort) tuple) to a samizdat
// UDP-over-CONNECT stream. Datagrams are length-framed inside an H2
// stream by the upstream samizdat client (see udp_packetconn.go).
func forwardUDP(ctx context.Context, conn *gonet.UDPConn, dest string, client *core.Client) {
	release, ok := acquireDial(ctx)
	if !ok {
		return
	}
	remote, err := client.DialUDP(ctx, dest)
	release()
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

func isIPv6Address(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// dialSem caps parallel outbound dials across both TCP and UDP forwarders.
// Without this, a Speedtest plus parallel iOS DNS resolutions can fan out
// to 200-500 simultaneous H2 stream openings, which (a) blows past the
// samizdat connpool's per-conn stream limit and triggers a TLS handshake
// storm to spin up new transports, and (b) explodes goroutine count from
// the baseline 250 to 800+ in 10 s — well past the iOS extension's RAM
// budget. 48 is a deliberately conservative ceiling: typical browsing is
// well under it, Speedtest peaks at ~16-32 real flows, and any dial that
// sees the channel full just drops the request rather than queueing
// behind a slow handshake.
var dialSem = make(chan struct{}, 48)
var dialDropCount int
var dialDropLastLog time.Time
var dialDropMu sync.Mutex

// acquireDial blocks until a slot is free or the context cancels. Returns
// (release, true) on success, (nil, false) on context cancel.
func acquireDial(ctx context.Context) (func(), bool) {
	select {
	case dialSem <- struct{}{}:
		return func() { <-dialSem }, true
	case <-ctx.Done():
		return nil, false
	default:
		// Channel full. Don't queue — the iOS app will retry naturally
		// (DNS resolvers, TCP SYN-retransmits) and we want to shed load
		// rather than build a goroutine queue.
		dialDropMu.Lock()
		first := dialDropCount == 0
		dialDropCount++
		throttled := !first && time.Since(dialDropLastLog) < 5*time.Second
		if !throttled {
			dialDropLastLog = time.Now()
		}
		count := dialDropCount
		dialDropMu.Unlock()
		if !throttled {
			rt.appendLog(fmt.Sprintf("warn: dial-cap reached, dropping (in_flight=48, total_drops=%d)", count))
		}
		return nil, false
	}
}

// dnsCache: short-TTL response cache so iOS doesn't re-tunnel the same
// query 50 times in a Speedtest cascade.
type dnsCacheEntry struct {
	response []byte
	expires  time.Time
}

var dnsCacheMu sync.Mutex
var dnsCache = map[string]dnsCacheEntry{}

const dnsCacheTTL = 30 * time.Second
const dnsCacheMax = 256

func dnsCacheGet(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	key := string(query[2:]) // skip transaction ID; questions+flags are stable
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	e, ok := dnsCache[key]
	if !ok || time.Now().After(e.expires) {
		return nil
	}
	// Splice the requester's transaction ID over the cached response.
	resp := make([]byte, len(e.response))
	copy(resp, e.response)
	if len(resp) >= 2 {
		resp[0] = query[0]
		resp[1] = query[1]
	}
	return resp
}

func dnsCachePut(query, response []byte) {
	if len(query) < 12 || len(response) < 12 {
		return
	}
	key := string(query[2:])
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if len(dnsCache) >= dnsCacheMax {
		// Crude eviction — drop a random ~half. Keeps the map small
		// without sorting all entries.
		for k := range dnsCache {
			delete(dnsCache, k)
			if len(dnsCache) < dnsCacheMax/2 {
				break
			}
		}
	}
	dnsCache[key] = dnsCacheEntry{
		response: append([]byte(nil), response...),
		expires:  time.Now().Add(dnsCacheTTL),
	}
}

// noteIPv6Drop logs the first IPv6 destination drop loudly and the rest at
// 1-per-30s to keep the buffer readable when an iOS app sprays QUIC at a
// dozen Google AAAAs.
var ipv6DropMu sync.Mutex
var ipv6DropCount int
var ipv6DropLastLog time.Time

func noteIPv6Drop(proto, dest string) {
	ipv6DropMu.Lock()
	first := ipv6DropCount == 0
	ipv6DropCount++
	throttled := !first && time.Since(ipv6DropLastLog) < 30*time.Second
	if !throttled {
		ipv6DropLastLog = time.Now()
	}
	count := ipv6DropCount
	ipv6DropMu.Unlock()
	if !throttled {
		rt.appendLog(fmt.Sprintf("info: dropping IPv6 %s dest %s (server has no v6 uplink) [total=%d]", proto, dest, count))
	}
}

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
