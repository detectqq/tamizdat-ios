//go:build netstack_real

package netstack

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
)

// utun fd protocol on iOS NEPacketTunnelProvider darwin:
//
// **The fd returned by `packetFlow.value(forKeyPath: "socket.fileDescriptor")`
// uses the standard utun_control protocol — every read/write is
// prefixed with a 4-byte address-family header in NETWORK byte order
// (= htonl(AF_INET) = `00 00 00 02` for IPv4).** Verified against:
//   - hev-socks5-tunnel `src/hev-tunnel-macos.h:21-39`: readv/writev
//     with `htonl(AF_INET)` in iovec[0] for darwin path
//   - sing-tun `tun_darwin.go`: `PacketOffset = 4`, prefix
//     `{0x00, 0x00, 0x00, AF_INET}` (network order) used uniformly
//     whether the fd was opened internally or via Options.FileDescriptor
//   - Tun2SocksKit (a shipping iOS NE consumer of hev) hands the
//     KVO-scanned utun fd straight into hev's macOS path
//
// IPA-C1: AF prefix added with binary.BigEndian = network byte order
// (correct). But C1 silently failed because the impl files had
// `//go:build ios && netstack_real` — gomobile's iOS build didn't
// match the `ios` tag → stub linked. Misdiagnosed as endianness.
//
// IPA-C2: dropped the `ios` build tag (correct fix), but
// "fixed" endianness from BigEndian to NativeEndian (= LittleEndian on
// arm64). Wrong direction — that produced `02 00 00 00` instead of
// `00 00 00 02`. iOS kernel rejected outbound writes silently.
//
// IPA-C4: misread hev's Linux/FreeBSD path (which DOES use raw IP)
// as evidence that iOS doesn't need AF prefix either. Removed prefix
// entirely. parseIPv4 then started receiving `00 00 00 02 45 ...`
// (the prefix iOS still sent), saw `0x00>>4 != 4`, returned false —
// silent drop of every packet. Symptom: pps=0, "ничего не открывает".
//
// IPA-C5 (this version): reverts to C1's correct BigEndian + 4-byte
// prefix while keeping C2's build tag fix + C3's no-bind() + C4's
// UAF fix.
const utunHdrLen = 4

const (
	afINET  = 2  // darwin AF_INET
	afINET6 = 30 // darwin AF_INET6
)

// pktBufSize matches utun MTU + 4-byte AF prefix.
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

// readUtun reads one packet from the utun fd. Strips the 4-byte AF
// prefix and returns the IP-header-and-payload slice + the AF tag
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
	// AF prefix is network-byte-order uint32 on darwin (= htonl(AF_INET)).
	afTag = binary.BigEndian.Uint32(buf[0:4])
	return afTag, buf[utunHdrLen:n], nil
}

// writeUtun writes one packet to the utun fd. ipPkt is the IP header
// + payload (without the 4-byte AF prefix). Caller supplies a backing
// buffer with at least utunHdrLen bytes of headroom AT buf[0:utunHdrLen]
// — we'll write the AF prefix there in network byte order.
//
// Convention: caller has already filled buf[utunHdrLen:utunHdrLen+ipLen]
// and tells us ipLen.
func writeUtun(fd int, buf *[pktBufSize]byte, afTag uint32, ipLen int) error {
	binary.BigEndian.PutUint32(buf[0:4], afTag)
	_, err := syscall.Write(fd, buf[:utunHdrLen+ipLen])
	return err
}
