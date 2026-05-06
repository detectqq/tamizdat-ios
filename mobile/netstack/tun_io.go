//go:build ios && netstack_real

package netstack

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
)

// utun fd protocol on darwin: every read/write is prefixed with a 4-byte
// "address family" header (host byte order). Bytes 0-3 = AF_INET (=2)
// or AF_INET6 (=30) when packed for the utun_control socket. We strip
// it on read, prepend it on write.
//
// Reference: Apple's source comments + lwIP-on-darwin implementations
// (e.g. hev-socks5-tunnel src/hev-tun.c, sing-tun's tun_darwin.go
// readPacketDarwin / writePacketDarwin).
const utunHdrLen = 4

const (
	afINET  = 2  // darwin AF_INET
	afINET6 = 30 // darwin AF_INET6
)

// pktBufSize matches our advertised utun MTU exactly. iOS NE
// NEPacketTunnelNetworkSettings.mtu = 4064 (sing-box-for-apple
// recommendation, per project_ios_singtun_ground_truth.md). +
// utun's 4-byte AF prefix.
//
// Comment on the empirical sweet spot: above 4064 (= 4096-UTUN_IF_HEADROOM_SIZE)
// the tun-loop performance "drops significantly... may be a system bug"
// per sing-box source comment at protocol/tun/inbound.go:107. Below
// 4064 means more iovec scratch + 3-4× syscalls per byte.
const (
	tunMTU      = 4064
	pktBufSize  = tunMTU + utunHdrLen
	pktPoolCap  = 64 // max idle buffers in pool; surplus get GC'd
)

// pktBufPool is the central scratch pool for utun read/write. Every
// packet path beats through this pool — read→parse→dispatch→build-reply
// reuses the same buffer when it can.
//
// Why custom pool with cap rather than sync.Pool: sync.Pool drains
// between GC cycles, so under burst we'd reallocate 64 fresh buffers
// every 30s. A bounded chan-backed pool keeps a small working set
// "warm". Pool overflow falls back to allocation; under-load excess
// buffers get GC'd via channel drain in pktPool.put.
//
// Buffer lifetime:
//   - pktPool.get() returns a *[pktBufSize]byte
//   - caller fills b[utunHdrLen:n+utunHdrLen] with packet data via syscall
//   - on dispatch completion, caller calls pktPool.put(b)
type pktPool struct {
	ch chan *[pktBufSize]byte
}

func newPktPool() *pktPool {
	return &pktPool{ch: make(chan *[pktBufSize]byte, pktPoolCap)}
}

func (p *pktPool) get() *[pktBufSize]byte {
	select {
	case b := <-p.ch:
		return b
	default:
		var b [pktBufSize]byte
		return &b
	}
}

func (p *pktPool) put(b *[pktBufSize]byte) {
	select {
	case p.ch <- b:
	default:
		// Pool full, let GC reclaim. Avoids unbounded memory hold under
		// transient burst.
	}
}

// fallback fixed pool fallback for sync.Pool callsites that prefer
// the standard interface.
var sharedPktPool = sync.Pool{
	New: func() any {
		var b [pktBufSize]byte
		return &b
	},
}

// readUtun reads one packet from the utun fd. Returns the IP-header-and-
// payload slice (the 4-byte AF prefix has been stripped) and the AF tag
// (afINET=2 or afINET6=30). The slice is sliced into the supplied
// backing buffer; do NOT modify until done with the read.
//
// Caller MUST call pool.put(buf) when finished with the returned slice.
func readUtun(fd int, buf *[pktBufSize]byte) (afTag uint32, ip []byte, err error) {
	n, err := syscall.Read(fd, buf[:])
	if err != nil {
		return 0, nil, err
	}
	if n < utunHdrLen {
		return 0, nil, fmt.Errorf("utun read short: %d bytes", n)
	}
	// AF prefix is host-byte-order uint32 on darwin.
	afTag = binary.BigEndian.Uint32(buf[0:4])
	return afTag, buf[utunHdrLen:n], nil
}

// writeUtun writes one packet to the utun fd. ipPkt is the IP header
// + payload (without the 4-byte AF prefix). Caller supplies a backing
// buffer with at least utunHdrLen bytes of headroom AT buf[0:utunHdrLen]
// — we'll write the AF prefix there.
//
// Convention: caller has already filled buf[utunHdrLen:utunHdrLen+ipLen]
// and tells us ipLen.
func writeUtun(fd int, buf *[pktBufSize]byte, afTag uint32, ipLen int) error {
	binary.BigEndian.PutUint32(buf[0:4], afTag)
	_, err := syscall.Write(fd, buf[:utunHdrLen+ipLen])
	return err
}
