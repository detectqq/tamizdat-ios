package samizdat

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxUDPDatagram is the maximum payload size of a single tunneled UDP datagram.
const MaxUDPDatagram = 65535

// SamizdatProtocolHeader names the request/response header used to negotiate
// non-TCP transports inside the H2 CONNECT tunnel. Today only "udp/1" is defined.
const SamizdatProtocolHeader = "Samizdat-Protocol"

// SamizdatProtocolUDP is the value used for UDP-over-CONNECT.
const SamizdatProtocolUDP = "udp/1"

// udpFramedPacketConn implements net.PacketConn over a length-prefixed
// bidirectional stream (H2 stream body + ResponseWriter, or a server-side
// equivalent). All datagrams travel as `uint16 BE length || payload`.
//
// All reads return the originally negotiated remote address (the CONNECT
// target). Writes are silently restricted to that address -- packets directed
// elsewhere are rejected. tun2socks's `symmetricNATPacketConn`
// (tun2socks/v2/tunnel/udp.go) filters by source string, so we MUST return
// the same Addr.String() that DialUDP's metadata had.
//
// HIGH-1 caveat (known): SetDeadline only takes effect at the start of the
// next ReadFrom/WriteTo call -- it does not unblock a Read already parked
// inside io.ReadFull. Callers wanting prompt cancellation should Close().
type udpFramedPacketConn struct {
	rwc       io.ReadWriteCloser // the stream (h2 RoundTrip body or server stream)
	target    net.Addr           // target the CONNECT was made for; ReadFrom returns this
	closeOnce sync.Once
	closed    atomic.Bool

	wmu sync.Mutex // serialize writes (one Write per datagram)
	rmu sync.Mutex // serialize reads (one ReadFull per datagram)

	// deadline timers (atomic int for lockless cmpxchg)
	rd atomic.Int64 // unix nano
	wd atomic.Int64
}

func newUDPFramedPacketConn(rwc io.ReadWriteCloser, target net.Addr) *udpFramedPacketConn {
	return &udpFramedPacketConn{rwc: rwc, target: target}
}

// ReadFrom reads one UDP datagram. The address returned is always the
// original CONNECT target (so tun2socks's symmetric-NAT filter accepts it).
func (c *udpFramedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if t := c.rd.Load(); t != 0 {
		now := time.Now().UnixNano()
		if t <= now {
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: timeoutErr{}}
		}
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var hdr [2]byte
	if _, err := io.ReadFull(c.rwc, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(p) {
		// drain to keep the stream parseable, then signal short buffer
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.rwc, buf); err != nil {
			return 0, nil, err
		}
		copy(p, buf)
		return len(p), c.target, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(c.rwc, p[:n]); err != nil {
		return 0, nil, err
	}
	return n, c.target, nil
}

// WriteTo writes one UDP datagram. The address must match the original
// CONNECT target (tun2socks always passes the same metadata.DestinationAddress).
func (c *udpFramedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > MaxUDPDatagram {
		return 0, errors.New("samizdat: udp datagram too large")
	}
	// Defensive: tun2socks always uses the same target, but reject divergent
	// destinations so we don't silently swallow buggy callers.
	if addr != nil && c.target != nil &&
		!strings.EqualFold(addr.String(), c.target.String()) {
		return 0, errors.New("samizdat: udp tunnel is bound to a single target")
	}
	if t := c.wd.Load(); t != 0 {
		now := time.Now().UnixNano()
		if t <= now {
			return 0, &net.OpError{Op: "write", Net: "udp", Err: timeoutErr{}}
		}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	if _, err := c.rwc.Write(hdr[:]); err != nil {
		return 0, err
	}
	if _, err := c.rwc.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpFramedPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		err = c.rwc.Close()
	})
	return err
}

func (c *udpFramedPacketConn) LocalAddr() net.Addr { return localUDPAddr{} }

func (c *udpFramedPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *udpFramedPacketConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.rd.Store(0)
	} else {
		c.rd.Store(t.UnixNano())
	}
	return nil
}

func (c *udpFramedPacketConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.wd.Store(0)
	} else {
		c.wd.Store(t.UnixNano())
	}
	return nil
}

type localUDPAddr struct{}

func (localUDPAddr) Network() string { return "udp" }
func (localUDPAddr) String() string  { return "samizdat-udp-tunnel" }

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }
