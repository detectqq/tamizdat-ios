package wgturnclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

const (
	workerSendBuf      = 128
	sessionReadTimeout = 60 * time.Second
	readBufSize        = 1600
	socketBufSize      = 625 * 1024
	// Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696.
	// Cap concurrent DTLS handshakes to 3 to stop the OK CDN TURN
	// server from rate-limiting the whole worker group when many
	// sessions race to start at the same moment (worker-group rotation
	// or app cold-start). 3 is the upstream value; matches what their
	// production client ships with.
	handshakeSemCap     = 3
	handshakeAcquireTTL = 5 * time.Second
)

// handshakeSem throttles concurrent DTLS Client handshakes against
// the TURN server. Package-level so all worker groups inside one
// process share the same budget — the upstream client uses the same
// scope. iOS test/release ship a single Runner per process, so the
// distinction does not matter today, but keeping the scope identical
// to upstream avoids drift when porting future fixes.
//
// Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696
// (client/main.go:66, 1404-1409).
var handshakeSem = make(chan struct{}, handshakeSemCap)

type dtlsHandshaker interface {
	HandshakeContext(context.Context) error
}

func runDTLSHandshakeWithThrottle(sessCtx context.Context, sessionID int, conn dtlsHandshaker) error {
	// Acquire one slot from the package-level handshake throttle before
	// running the DTLS handshake. The slot is released immediately after
	// HandshakeContext returns: it must cap concurrent handshakes, not
	// long-lived relay sessions.
	acqCtx, acqCancel := context.WithTimeout(sessCtx, handshakeAcquireTTL)
	select {
	case handshakeSem <- struct{}{}:
		acqCancel()
	case <-acqCtx.Done():
		acqCancel()
		return fmt.Errorf("DTLS handshake throttle: не удалось получить слот за %s (все %d заняты)", handshakeAcquireTTL, handshakeSemCap)
	}

	hctx, hcancel := context.WithTimeout(sessCtx, 45*time.Second)
	log.Printf("[ВОРКЕР #%d] [DTLS] Рукопожатие (Handshake)...", sessionID)
	err := conn.HandshakeContext(hctx)
	hcancel()
	<-handshakeSem
	if err != nil {
		return fmt.Errorf("DTLS хендшейк: %w", err)
	}
	log.Printf("[ВОРКЕР #%d] [DTLS] Соединение установлено ✓", sessionID)
	return nil
}

// NullLoggerFactory подавляет логи pion
type NullLoggerFactory struct{}

func (n *NullLoggerFactory) NewLogger(_ string) logging.LeveledLogger { return &NullLogger{} }

type NullLogger struct{}

func (n *NullLogger) Trace(_ string)                    {}
func (n *NullLogger) Tracef(_ string, _ ...interface{}) {}
func (n *NullLogger) Debug(_ string)                    {}
func (n *NullLogger) Debugf(_ string, _ ...interface{}) {}
func (n *NullLogger) Info(_ string)                     {}
func (n *NullLogger) Infof(_ string, _ ...interface{})  {}
func (n *NullLogger) Warn(_ string)                     {}
func (n *NullLogger) Warnf(_ string, _ ...interface{})  {}
func (n *NullLogger) Error(_ string)                    {}
func (n *NullLogger) Errorf(_ string, _ ...interface{}) {}

// connectedUDPConn — обёртка для connected UDP socket → PacketConn
type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

type turnEndpoint struct {
	Addr      string
	Scheme    string
	Transport string
	Proto     string
	UseUDP    bool
	UseTLS    bool
}

func selectTurnEndpoint(creds *Credentials, sessionID int, preferUDP bool) (turnEndpoint, error) {
	if creds == nil {
		return turnEndpoint{}, fmt.Errorf("пустые TURN учетные данные")
	}
	if len(creds.TurnServers) > 0 {
		matching := make([]turnEndpoint, 0, len(creds.TurnServers))
		fallback := make([]turnEndpoint, 0, len(creds.TurnServers))
		for _, server := range creds.TurnServers {
			ep, ok := endpointFromTurnServer(server)
			if !ok {
				continue
			}
			if ep.UseUDP == preferUDP {
				matching = append(matching, ep)
			} else {
				fallback = append(fallback, ep)
			}
		}
		if len(matching) == 0 {
			matching = fallback
		}
		if len(matching) == 0 {
			return turnEndpoint{}, fmt.Errorf("нет поддерживаемых TURN endpoints")
		}
		return matching[positiveModulo(sessionID, len(matching))], nil
	}
	if len(creds.TurnURLs) == 0 {
		return turnEndpoint{}, fmt.Errorf("нет TURN URL в учетных данных")
	}
	addr := strings.TrimSpace(creds.TurnURLs[positiveModulo(sessionID, len(creds.TurnURLs))])
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return turnEndpoint{}, fmt.Errorf("разбор TURN URL %q: %w", addr, err)
	}
	proto := "TCP"
	transport := "tcp"
	if preferUDP {
		proto = "UDP"
		transport = "udp"
	}
	return turnEndpoint{
		Addr:      addr,
		Scheme:    "turn",
		Transport: transport,
		Proto:     proto,
		UseUDP:    preferUDP,
	}, nil
}

func endpointFromTurnServer(server TurnServer) (turnEndpoint, bool) {
	host := strings.TrimSpace(server.Host)
	if host == "" || server.Port <= 0 {
		return turnEndpoint{}, false
	}
	scheme := strings.ToLower(strings.TrimSpace(server.Scheme))
	if scheme == "" {
		scheme = "turn"
	}
	transport := strings.ToLower(strings.TrimSpace(server.Transport))
	if transport == "" {
		if scheme == "turns" {
			transport = "tcp"
		} else {
			transport = "udp"
		}
	}
	if transport != "udp" && transport != "tcp" {
		transport = "udp"
	}
	useTLS := scheme == "turns"
	useUDP := transport == "udp" && !useTLS
	proto := "TCP"
	if useUDP {
		proto = "UDP"
	} else if useTLS {
		proto = "TLS"
		transport = "tcp"
	}
	return turnEndpoint{
		Addr:      net.JoinHostPort(host, fmt.Sprintf("%d", server.Port)),
		Scheme:    scheme,
		Transport: transport,
		Proto:     proto,
		UseUDP:    useUDP,
		UseTLS:    useTLS,
	}, true
}

func positiveModulo(value, mod int) int {
	if mod <= 0 {
		return 0
	}
	result := value % mod
	if result < 0 {
		result += mod
	}
	return result
}

func RunSession(
	ctx context.Context,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	useUDP bool,
	getConfig bool,
	configCh chan<- string,
	sessionID int,
	creds *Credentials,
	deviceID, password string,
	stats *Stats,
) (bool, error) {
	configDelivered := false

	endpoint, err := selectTurnEndpoint(creds, sessionID, useUDP)
	if err != nil {
		return false, err
	}

	urlhost, urlport, err := net.SplitHostPort(endpoint.Addr)
	if err != nil {
		return false, fmt.Errorf("разбор TURN URL %q: %w", endpoint.Addr, err)
	}
	if tp.Host != "" {
		urlhost = tp.Host
	}
	if tp.Port != "" {
		urlport = tp.Port
	}
	turnAddr := net.JoinHostPort(urlhost, urlport)

	// Транспорт: UDP, TCP, или TURNS/TLS over TCP.
	var turnConn net.PacketConn
	proto := endpoint.Proto

	if endpoint.UseUDP {
		resolved, err := net.ResolveUDPAddr("udp", turnAddr)
		if err != nil {
			return false, fmt.Errorf("резолв TURN: %w", err)
		}
		c, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			return false, fmt.Errorf("подключение TURN UDP: %w", err)
		}
		defer c.Close()
		_ = c.SetReadBuffer(socketBufSize)
		_ = c.SetWriteBuffer(socketBufSize)
		turnConn = &connectedUDPConn{c}
	} else {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		var c net.Conn
		var dialErr error
		if endpoint.UseTLS {
			c, dialErr = tls.DialWithDialer(dialer, "tcp", turnAddr, &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: strings.Trim(urlhost, "[]"),
			})
		} else {
			c, dialErr = dialer.Dial("tcp", turnAddr)
		}
		if dialErr != nil {
			return false, fmt.Errorf("подключение TURN %s: %w", proto, dialErr)
		}
		defer c.Close()
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetReadBuffer(socketBufSize)
			_ = tc.SetWriteBuffer(socketBufSize)
		}
		turnConn = turn.NewSTUNConn(c)
	}
	log.Printf("[СЕССИЯ #%d] TURN %s (scheme=%s transport=%s proto=%s)", sessionID, turnAddr, endpoint.Scheme, endpoint.Transport, proto)

	// TURN Client (pion/turn/v5)
	tc, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Conn:           turnConn,
		Username:       creds.User,
		Password:       creds.Pass,
		LoggerFactory:  &NullLoggerFactory{},
	})
	if err != nil {
		return false, fmt.Errorf("TURN клиент: %w", err)
	}
	defer tc.Close()

	if err = tc.Listen(); err != nil {
		return false, fmt.Errorf("TURN Listen: %w", err)
	}

	relay, err := tc.Allocate()
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "Quota") || strings.Contains(errStr, "486") {
			return false, fmt.Errorf("TURN квота: %w", err)
		}
		return false, fmt.Errorf("TURN Allocate: %w", err)
	}
	defer relay.Close()
	log.Printf("[СЕССИЯ #%d] Relay: %s", sessionID, relay.LocalAddr())

	// Pipe для DTLS ↔ TURN relay
	pipeA, pipeB := connutil.AsyncPacketPipe()

	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()

	// Keepalive goroutine
	var sessionWg sync.WaitGroup
	sessionWg.Add(1)
	go func() {
		defer sessionWg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-t.C:
				tc.SendBindingRequest()
			}
		}
	}()

	// Relay ↔ Pipe proxy
	var relayWg sync.WaitGroup
	relayWg.Add(2)

	stopRelay := context.AfterFunc(sessCtx, func() {
		_ = relay.SetDeadline(time.Now())
		_ = pipeA.SetDeadline(time.Now())
	})
	defer stopRelay()

	// relay → pipeA
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		b := make([]byte, readBufSize)
		for {
			n, _, readErr := relay.ReadFrom(b)
			if readErr != nil {
				return
			}
			if _, writeErr := pipeA.WriteTo(b[:n], peer); writeErr != nil {
				return
			}
		}
	}()

	// pipeA → relay
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		b := make([]byte, readBufSize)
		for {
			n, _, readErr := pipeA.ReadFrom(b)
			if readErr != nil {
				return
			}
			if _, writeErr := relay.WriteTo(b[:n], peer); writeErr != nil {
				return
			}
		}
	}()

	// DTLS с поддержкой Connection ID
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return false, fmt.Errorf("генерация сертификата: %w", err)
	}

	sni := tp.Sni
	if sni == "" {
		sni = "calls.okcdn.ru"
	}

	dtlsCfg := &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(), // client_id support
		ServerName:            sni,
	}

	dtlsConn, err := dtls.Client(pipeB, peer, dtlsCfg)
	if err != nil {
		return false, fmt.Errorf("DTLS клиент: %w", err)
	}
	defer dtlsConn.Close()

	if err := runDTLSHandshakeWithThrottle(sessCtx, sessionID, dtlsConn); err != nil {
		return false, err
	}

	atomic.AddInt32(&stats.ActiveConnections, 1)
	defer atomic.AddInt32(&stats.ActiveConnections, -1)

	// Запрос конфига
	if getConfig && configCh != nil {
		conf, confErr := RequestConfig(dtlsConn, localPort, deviceID, password)
		if confErr != nil {
			errStr := confErr.Error()
			if strings.Contains(errStr, "FATAL_AUTH") {
				return false, confErr
			}
			log.Printf("[ВОРКЕР #%d] Ошибка конфига: %v", sessionID, confErr)
		} else if conf != "" {
			select {
			case configCh <- conf:
				configDelivered = true
				log.Printf("[ВОРКЕР #%d] Конфиг получен", sessionID)
			default:
				configDelivered = true
				log.Printf("[ВОРКЕР #%d] Конфиг уже был доставлен другим воркером", sessionID)
			}
		} else {
			log.Printf("[ВОРКЕР #%d] Сервер ещё не выдал WireGuard-конфиг, повторим позже", sessionID)
		}
	}

	// READY (Удалено! Передача трафика начинается моментально без подтверждений)
	log.Printf("[ВОРКЕР #%d] [READY] Туннель готов к работе ✓", sessionID)

	// Регистрация в диспетчере
	slot := &WorkerSlot{
		ID:     sessionID,
		SendCh: make(chan []byte, workerSendBuf),
	}
	d.Register(slot)
	defer d.Unregister(slot)

	// Proxy DTLS ↔ Dispatcher
	var proxyWg sync.WaitGroup
	proxyWg.Add(2)

	stopDTLS := context.AfterFunc(sessCtx, func() {
		_ = dtlsConn.SetDeadline(time.Now())
	})
	defer stopDTLS()

	// Writer: dispatcher → DTLS
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		var lastWriteDeadline time.Time
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				_ = dtlsConn.SetWriteDeadline(now.Add(5 * time.Second))
				lastWriteDeadline = now
				if _, writeErr := dtlsConn.Write([]byte("WAKEUP")); writeErr != nil {
					log.Printf("[ВОРКЕР #%d] Ошибка Writer (WAKEUP): %v", sessionID, writeErr)
					return
				}
			case pkt, ok := <-slot.SendCh:
				if !ok {
					return
				}
				now := time.Now()
				if now.Sub(lastWriteDeadline) > 5*time.Second {
					_ = dtlsConn.SetWriteDeadline(now.Add(10 * time.Second))
					lastWriteDeadline = now
				}
				if _, writeErr := dtlsConn.Write(pkt); writeErr != nil {
					log.Printf("[ВОРКЕР #%d] Ошибка Writer (Payload): %v", sessionID, writeErr)
					return
				}
			}
		}
	}()

	// Reader: DTLS → dispatcher
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		b := make([]byte, 2000)
		var lastReadDeadline time.Time
		for {
			now := time.Now()
			if now.Sub(lastReadDeadline) > 10*time.Second {
				_ = dtlsConn.SetReadDeadline(now.Add(sessionReadTimeout))
				lastReadDeadline = now
			}
			n, readErr := dtlsConn.Read(b)
			if readErr != nil {
				if sessCtx.Err() != nil {
					// Контекст был отменен (ротация/уничтожение батча)
					return
				}
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					continue
				}
				log.Printf("[ВОРКЕР #%d] Ошибка Reader: %v", sessionID, readErr)
				return
			}

			if n == 6 && string(b[:6]) == "WAKEUP" {
				continue
			}

			pkt := make([]byte, n)
			copy(pkt, b[:n])
			select {
			case d.ReturnCh <- pkt:
			case <-sessCtx.Done():
				return
			}
		}
	}()

	proxyWg.Wait()
	sessCancel()
	relayWg.Wait()
	sessionWg.Wait()
	_ = pipeA.Close()
	_ = pipeB.Close()
	log.Printf("[СЕССИЯ #%d] Завершена", sessionID)
	return configDelivered, nil
}
