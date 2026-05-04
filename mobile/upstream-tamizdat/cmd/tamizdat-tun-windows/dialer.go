//go:build windows

package main

import (
	"net/netip"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/detectqq/tamizdat"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// errJunkDestination is returned when the destination IP is link-local,
// multicast, or a broadcast address — these are unroutable on the public
// internet and would just waste a CONNECT round-trip + log noise.
var errJunkDestination = errors.New("destination is link-local/multicast/broadcast — not tunnelable")

// errUDPDialFailed wraps a UDP-tunnel open failure (was: stub returning
// "does not transport UDP" prior to wiring up H2-CONNECT UDP/1 protocol).
var errUDPDialFailed = errors.New("tamizdat UDP relay failed")

// isJunkDestination filters out destinations that won't survive an internet
// round-trip: link-local (169.254/16), multicast (224.0.0.0/4), limited
// broadcast (255.255.255.255), zero (0.0.0.0). These come from Windows
// auto-IP (NetBIOS broadcasts), mDNS, LLMNR, etc — silent local-drop is
// correct.
func isJunkDestination(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	if addr.Is4() {
		v4 := addr.As4()
		// 255.255.255.255 limited broadcast
		if v4[0] == 0xff && v4[1] == 0xff && v4[2] == 0xff && v4[3] == 0xff {
			return true
		}
		// 169.254/16 link-local (already covered by IsLinkLocalUnicast but
		// belt-and-braces in case the netip detection is conservative)
		if v4[0] == 169 && v4[1] == 254 {
			return true
		}
	}
	return false
}



type samizdatProxyDialer struct {
	client *tamizdat.Client
	debug  bool
	// silent UDP counters: log a summary once per logEvery interval instead of per-flow spam
	udpDropped          atomic.Uint64
	ipv6Drops           atomic.Uint64
	backpressureRetries atomic.Uint64
	stopOnce            atomic.Bool
}

const udpLogEvery = 30 * time.Second

func newSamizdatProxyDialer(client *tamizdat.Client, debug bool) *samizdatProxyDialer {
	d := &samizdatProxyDialer{client: client, debug: debug}
	go d.summaryLoop()
	return d
}

func (d *samizdatProxyDialer) summaryLoop() {
	t := time.NewTicker(udpLogEvery)
	defer t.Stop()
	for range t.C {
		if d.stopOnce.Load() {
			return
		}
		udp := d.udpDropped.Swap(0)
		v6 := d.ipv6Drops.Swap(0)
		bp := d.backpressureRetries.Swap(0)
		if udp == 0 && v6 == 0 && bp == 0 {
			continue
		}
		log.Printf("dropped %d UDP/junk %d IPv6 flows; %d dials retried after scheduler backpressure (last %s)", udp, v6, bp, udpLogEvery)
	}
}

func (d *samizdatProxyDialer) Stop() { d.stopOnce.Store(true) }

func (d *samizdatProxyDialer) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	if metadata == nil {
		return nil, errors.New("nil metadata")
	}
	if metadata.Network != M.TCP {
		// Should not happen — UDP goes via DialUDP — but guard anyway.
		d.udpDropped.Add(1)
		return nil, fmt.Errorf("unsupported network %s", metadata.Network)
	}
	if !metadata.DstIP.IsValid() {
		return nil, errors.New("invalid destination IP")
	}
	if isJunkDestination(metadata.DstIP) {
		// Silent local-drop. Aggregate counter via udpDropped (technically TCP
		// here but sharing the bucket avoids splitting the summary log).
		d.udpDropped.Add(1)
		return nil, errJunkDestination
	}
	if !metadata.DstIP.Is4() {
		d.ipv6Drops.Add(1)
		if d.debug {
			log.Printf("[ipv6 drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, fmt.Errorf("IPv6 destination %s disabled in v1", metadata.DestinationAddress())
	}

	dest := metadata.DestinationAddress()
	src := metadata.SourceAddress()
	startedAt := time.Now()
	log.Printf("[TCP-START] %s -> %s", src, dest)

	// Retry on scheduler backpressure (no outer transport with budget yet, prewarm in flight).
	// Browsers pump dozens of parallel TCP dials; first attempts may race ahead of prewarm.
	var (
		conn net.Conn
		err  error
	)
	for attempt := 0; attempt < 6; attempt++ {
		attemptStart := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err = d.client.DialContext(dialCtx, "tcp", dest)
		cancel()
		if err == nil {
			log.Printf("[TCP-OK]    %s -> %s after %d attempt(s) in %dms", src, dest, attempt+1, time.Since(startedAt).Milliseconds())
			return conn, nil
		}
		if !isBackpressure(err) {
			// Hard failure — not transient. Operator wants to see exactly where it fell apart.
			log.Printf("[TCP-FAIL]  %s -> %s after %d attempt(s) in %dms: %v",
				src, dest, attempt+1, time.Since(startedAt).Milliseconds(), err)
			return nil, err
		}
		d.backpressureRetries.Add(1)
		log.Printf("[TCP-WAIT]  %s -> %s attempt %d backpressure (%dms): %v",
			src, dest, attempt+1, time.Since(attemptStart).Milliseconds(), err)
		select {
		case <-ctx.Done():
			log.Printf("[TCP-CANCEL] %s -> %s after %d attempt(s) in %dms (ctx done)", src, dest, attempt+1, time.Since(startedAt).Milliseconds())
			return nil, ctx.Err()
		case <-time.After(time.Duration(50<<attempt) * time.Millisecond):
			// 50ms, 100ms, 200ms, 400ms, 800ms, 1600ms = ~3.15s total worst case
		}
	}
	log.Printf("[TCP-EXHAUSTED] %s -> %s all 6 attempts hit backpressure (%dms total): %v",
		src, dest, time.Since(startedAt).Milliseconds(), err)
	return nil, err
}

func isBackpressure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// All of these are TRANSIENT scheduler / outer-rotation states; retry hides them
	// from the gvisor netstack TCP layer (which would otherwise return RST to the app).
	return strings.Contains(s, "scheduler backpressure") ||
		strings.Contains(s, "ErrSchedulerBackpressure") ||
		strings.Contains(s, "transport is not active") ||
		strings.Contains(s, "no active transport") ||
		strings.Contains(s, "OPEN_STREAM") ||
		strings.Contains(s, "use of closed network connection") || // outer TCP died — pool will create fresh transport on retry
		strings.Contains(s, "transport closed") ||                // pool member self-marked dead
		strings.Contains(s, "transport draining") ||              // mid-rotation; next attempt picks the new one
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "GOAWAY")
}

func (d *samizdatProxyDialer) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	if metadata == nil {
		return nil, errors.New("nil metadata")
	}
	if !metadata.DstIP.IsValid() {
		return nil, errors.New("invalid destination IP")
	}
	if isJunkDestination(metadata.DstIP) {
		d.udpDropped.Add(1)
		// No log per-packet — summary every 30s shows count.
		return nil, errJunkDestination
	}
	if !metadata.DstIP.Is4() {
		d.ipv6Drops.Add(1)
		if d.debug {
			log.Printf("[ipv6 udp drop] %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
		}
		return nil, fmt.Errorf("IPv6 UDP destination %s disabled in v1", metadata.DestinationAddress())
	}
	dest := metadata.DestinationAddress()
	src := metadata.SourceAddress()
	startedAt := time.Now()
	log.Printf("[UDP-START] %s -> %s", src, dest)

	// Retry on transient backpressure (transport scheduler, prewarm in flight).
	var (
		pc  net.PacketConn
		err error
	)
	for attempt := 0; attempt < 4; attempt++ {
		dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		pc, err = d.client.DialUDP(dialCtx, dest)
		cancel()
		if err == nil {
			log.Printf("[UDP-OK]    %s -> %s after %d attempt(s) in %dms", src, dest, attempt+1, time.Since(startedAt).Milliseconds())
			return pc, nil
		}
		if !isBackpressure(err) {
			log.Printf("[UDP-FAIL]  %s -> %s after %d attempt(s) in %dms: %v",
				src, dest, attempt+1, time.Since(startedAt).Milliseconds(), err)
			d.udpDropped.Add(1)
			return nil, fmt.Errorf("%w: %s", errUDPDialFailed, err.Error())
		}
		d.backpressureRetries.Add(1)
		log.Printf("[UDP-WAIT]  %s -> %s attempt %d backpressure: %v", src, dest, attempt+1, err)
		time.Sleep(time.Duration(50<<attempt) * time.Millisecond)
	}
	log.Printf("[UDP-EXHAUSTED] %s -> %s 4 attempts in %dms: %v", src, dest, time.Since(startedAt).Milliseconds(), err)
	d.udpDropped.Add(1)
	return nil, fmt.Errorf("%w: %s", errUDPDialFailed, err.Error())
}
