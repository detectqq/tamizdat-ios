package node

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// SocksInbound is a SOCKS5 (RFC 1928) listener. Only CONNECT is implemented;
// BIND and UDP-ASSOCIATE return errors at the SOCKS5 layer.
//
// Auth: empty creds = NO AUTH; non-empty = USER/PASS (RFC 1929) and other
// methods are rejected.
type SocksInbound struct {
	tag      string
	listen   string
	username string
	password string

	ln     net.Listener
	closed atomic.Bool
}

func NewSocksInbound(tag, listen string, raw json.RawMessage) (*SocksInbound, error) {
	var s SocksSettings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("socks inbound %q settings: %w", tag, err)
		}
	}
	if listen == "" {
		return nil, fmt.Errorf("socks inbound %q: listen required", tag)
	}
	if (s.Username == "") != (s.Password == "") {
		return nil, fmt.Errorf("socks inbound %q: username and password must be set together", tag)
	}
	return &SocksInbound{
		tag:      tag,
		listen:   listen,
		username: s.Username,
		password: s.Password,
	}, nil
}

func (s *SocksInbound) Tag() string { return s.tag }

func (s *SocksInbound) Start(ctx context.Context, d InboundDispatcher) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.listen, err)
	}
	s.ln = ln
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			return err
		}
		go s.handle(ctx, c, d)
	}
}

func (s *SocksInbound) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *SocksInbound) handle(ctx context.Context, c net.Conn, d InboundDispatcher) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))

	if err := s.negotiate(c); err != nil {
		return
	}
	req, err := s.parseRequest(c)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	if tcpAddr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		req.SourceIP = tcpAddr.IP
	}
	req.InboundTag = s.tag

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tunnel, _, err := d.Dispatch(dctx, req)
	if err != nil {
		// 0x05 = connection refused
		_, _ = c.Write([]byte{0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer tunnel.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Bidirectional copy.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(tunnel, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, tunnel); done <- struct{}{} }()
	<-done
}

func (s *SocksInbound) authConfigured() bool {
	return s.username != "" || s.password != ""
}

func (s *SocksInbound) negotiate(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("not socks5")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	want := byte(0x00)
	if s.authConfigured() {
		want = 0x02
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = c.Write([]byte{0x05, 0xff})
		return fmt.Errorf("no acceptable method")
	}
	if _, err := c.Write([]byte{0x05, want}); err != nil {
		return err
	}
	if want != 0x02 {
		return nil
	}
	return s.authUserPass(c)
}

func (s *SocksInbound) authUserPass(c net.Conn) error {
	ver := make([]byte, 2)
	if _, err := io.ReadFull(c, ver); err != nil {
		return err
	}
	if ver[0] != 0x01 {
		_, _ = c.Write([]byte{0x01, 0x01})
		return fmt.Errorf("bad auth ver")
	}
	uname := make([]byte, int(ver[1]))
	if _, err := io.ReadFull(c, uname); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return err
	}
	pword := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pword); err != nil {
		return err
	}
	uok := subtle.ConstantTimeCompare([]byte(s.username), uname) == 1
	pok := subtle.ConstantTimeCompare([]byte(s.password), pword) == 1
	if !uok || !pok {
		_, _ = c.Write([]byte{0x01, 0x01})
		return fmt.Errorf("auth fail")
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}
	return nil
}

func (s *SocksInbound) parseRequest(c net.Conn) (*Request, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x05 {
		return nil, fmt.Errorf("bad ver")
	}
	if hdr[1] != 0x01 {
		// CMD other than CONNECT
		_, _ = c.Write([]byte{0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("only CONNECT supported")
	}
	var host string
	switch hdr[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, err
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return nil, err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, err
		}
		host = net.IP(buf).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("bad atyp")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(pb))

	return &Request{
		Network:    NetworkTCP,
		TargetHost: host,
		TargetPort: port,
	}, nil
}
