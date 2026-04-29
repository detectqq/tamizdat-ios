package samizdat

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// UDP tunnel server handler. Accepts CONNECT with Samizdat-Protocol: udp/1.
// Bridges length-prefixed UDP datagrams from the H2 stream to a single UDP
// target (the CONNECT authority) via a dedicated ephemeral net.UDPConn.

const (
	udpServerIdleTimeout = 60 * time.Second
	udpServerMaxDatagram = 65535
	udpServerReadPoll    = 2 * time.Second // polling tick so ctx cancellation propagates
)

func (s *Server) handleUDPCONNECT(w http.ResponseWriter, r *http.Request, destination string) {
	// CRIT-0: validate destination + dial resolved IP -- defeats SSRF
	// (private/loopback/cloud-metadata) and DNS-rebinding TOCTOU.
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		http.Error(w, "bad destination", http.StatusBadRequest)
		return
	}
	target, err := ResolveAndValidateDestination(r.Context(), host, port)
	if err != nil {
		s.logf("[samizdat-udp] rejected destination %s: %v", destination, err)
		http.Error(w, "destination rejected", http.StatusBadRequest)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		s.logf("[samizdat-udp] resolve %s: %v", destination, err)
		http.Error(w, "resolve failed", http.StatusBadGateway)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		s.logf("[samizdat-udp] dial %s: %v", destination, err)
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	defer udpConn.Close()

	// Send 200 OK to signal client the tunnel is ready.
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	s.logf("[samizdat-udp] OPEN %s", destination)

	// Bidirectional pump:
	//   downstream: H2 stream -> UDP socket (write to target)
	//   upstream:   UDP socket -> H2 stream (write framed responses to client)
	//
	// Both directions reset an idle timer; whichever idles for udpServerIdleTimeout
	// closes the tunnel. HIGH-3: when ctx is cancelled, udpConn.Close() in the
	// watchdog wakes any in-flight ReadFromUDP immediately rather than waiting
	// for the next deadline poll.
	idleResetCh := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Idle watchdog -- closes udpConn on idle/cancel to unblock ReadFromUDP.
	go func() {
		t := time.NewTimer(udpServerIdleTimeout)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = udpConn.Close() // HIGH-3: unblock blocking ReadFromUDP
				return
			case <-idleResetCh:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				t.Reset(udpServerIdleTimeout)
			case <-t.C:
				s.logf("[samizdat-udp] IDLE_CLOSE %s", destination)
				_ = udpConn.Close()
				cancel()
				return
			}
		}
	}()

	// Downstream: client -> H2 -> UDP target
	go func() {
		defer cancel()
		body := r.Body
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(body, hdr[:]); err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed") {
					s.logf("[samizdat-udp] dn-hdr %s: %v", destination, err)
				}
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if n == 0 {
				continue
			}
			if n > udpServerMaxDatagram {
				s.logf("[samizdat-udp] dn-oversize %s: %d", destination, n)
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(body, buf); err != nil {
				return
			}
			_ = udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := udpConn.Write(buf); err != nil {
				s.logf("[samizdat-udp] dn-write %s: %v", destination, err)
				return
			}
			select {
			case idleResetCh <- struct{}{}:
			default:
			}
		}
	}()

	// Upstream: UDP target -> H2 -> client. Short polling deadline so ctx
	// cancellation propagates within udpServerReadPoll seconds even if the
	// watchdog hasn't fired Close() yet.
	flusher, _ := w.(http.Flusher)
	rbuf := make([]byte, udpServerMaxDatagram)
	var hdr [2]byte
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(udpServerReadPoll))
		n, _, err := udpConn.ReadFromUDP(rbuf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if !strings.Contains(err.Error(), "use of closed") {
				s.logf("[samizdat-udp] up-read %s: %v", destination, err)
			}
			return
		}
		if n == 0 || n > udpServerMaxDatagram {
			continue
		}
		binary.BigEndian.PutUint16(hdr[:], uint16(n))
		if _, err := w.Write(hdr[:]); err != nil {
			return
		}
		if _, err := w.Write(rbuf[:n]); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case idleResetCh <- struct{}{}:
		default:
		}
	}
}
