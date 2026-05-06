//go:build netstack_real

// Package netstack — Path 5 / Option A custom userspace TCP+UDP for iOS NE.
// This file: IPv4 + TCP + UDP header parse/build with zero allocations.
//
// All functions take/return byte slices into the caller's buffer; no
// allocation on the hot path. Checksums computed in-place via the
// classic 1's-complement RFC 1071 algorithm.
package netstack

import (
	"encoding/binary"
	"net/netip"
)

// IPv4 wire layout (RFC 791):
//   0-1   ver+ihl+tos
//   2-3   total length
//   4-5   id
//   6-7   flags+fragoff
//   8     ttl
//   9     proto
//   10-11 checksum
//   12-15 src addr
//   16-19 dst addr
//   20+   options OR payload (start at ihl*4)
//
// We only handle ihl=5 (no options). iOS apps don't usually send IP options
// to a tunnel; if they do we just ignore the option bytes — the iOS stack
// won't complain because we only echo what we received.
const ipv4MinHeader = 20

// TCP wire layout (RFC 793):
//   0-1   src port
//   2-3   dst port
//   4-7   seq
//   8-11  ack
//   12    data-off (high 4 bits) + reserved (low 4)
//   13    flags (CWR|ECE|URG|ACK|PSH|RST|SYN|FIN)
//   14-15 window
//   16-17 checksum
//   18-19 urgent ptr
//   20+   options OR payload (start at dataOff*4)
const (
	tcpMinHeader = 20

	tcpFIN = 1 << 0
	tcpSYN = 1 << 1
	tcpRST = 1 << 2
	tcpPSH = 1 << 3
	tcpACK = 1 << 4
	tcpURG = 1 << 5
)

const (
	udpHeader  = 8
	protoTCP   = 6
	protoUDP   = 17
	protoICMP4 = 1
)

// parsedV4 is a zero-alloc view into the caller's buffer.
type parsedV4 struct {
	src, dst netip.Addr
	proto    byte
	ihl      int // bytes
	tot      int // total IP length per header
	payload  []byte
}

// parseIPv4 returns a pointer into the supplied buffer. If the buffer
// is too short or version != 4, returns false. Zero allocation.
func parseIPv4(b []byte) (parsedV4, bool) {
	if len(b) < ipv4MinHeader {
		return parsedV4{}, false
	}
	if b[0]>>4 != 4 {
		return parsedV4{}, false
	}
	ihl := int(b[0]&0x0f) << 2
	if ihl < ipv4MinHeader || ihl > len(b) {
		return parsedV4{}, false
	}
	tot := int(binary.BigEndian.Uint16(b[2:4]))
	if tot > len(b) {
		// Truncated. Use what we have.
		tot = len(b)
	}
	if tot < ihl {
		return parsedV4{}, false
	}
	var src, dst netip.Addr
	src = netip.AddrFrom4(*(*[4]byte)(b[12:16]))
	dst = netip.AddrFrom4(*(*[4]byte)(b[16:20]))
	return parsedV4{
		src:     src,
		dst:     dst,
		proto:   b[9],
		ihl:     ihl,
		tot:     tot,
		payload: b[ihl:tot],
	}, true
}

// parsedTCP — zero-alloc view into the TCP segment.
type parsedTCP struct {
	srcPort, dstPort uint16
	seq, ack         uint32
	dataOff          int // bytes
	flags            byte
	window           uint16
	payload          []byte
}

func parseTCP(b []byte) (parsedTCP, bool) {
	if len(b) < tcpMinHeader {
		return parsedTCP{}, false
	}
	dataOff := int(b[12]>>4) << 2
	if dataOff < tcpMinHeader || dataOff > len(b) {
		return parsedTCP{}, false
	}
	return parsedTCP{
		srcPort: binary.BigEndian.Uint16(b[0:2]),
		dstPort: binary.BigEndian.Uint16(b[2:4]),
		seq:     binary.BigEndian.Uint32(b[4:8]),
		ack:     binary.BigEndian.Uint32(b[8:12]),
		dataOff: dataOff,
		flags:   b[13],
		window:  binary.BigEndian.Uint16(b[14:16]),
		payload: b[dataOff:],
	}, true
}

type parsedUDP struct {
	srcPort, dstPort uint16
	length           uint16
	payload          []byte
}

func parseUDP(b []byte) (parsedUDP, bool) {
	if len(b) < udpHeader {
		return parsedUDP{}, false
	}
	length := binary.BigEndian.Uint16(b[4:6])
	if int(length) < udpHeader {
		return parsedUDP{}, false
	}
	end := int(length)
	if end > len(b) {
		end = len(b)
	}
	return parsedUDP{
		srcPort: binary.BigEndian.Uint16(b[0:2]),
		dstPort: binary.BigEndian.Uint16(b[2:4]),
		length:  length,
		payload: b[udpHeader:end],
	}, true
}

// buildIPv4 writes a 20-byte IPv4 header into b[0:20]. Caller has filled
// b[20:end] with payload (TCP+data or UDP+data). Total length = end.
// Computes header checksum.
func buildIPv4(b []byte, src, dst netip.Addr, proto byte, end int) {
	_ = b[ipv4MinHeader-1]
	b[0] = 0x45 // ver=4, ihl=5
	b[1] = 0    // tos
	binary.BigEndian.PutUint16(b[2:4], uint16(end))
	binary.BigEndian.PutUint16(b[4:6], 0) // id; iOS doesn't seem to care
	binary.BigEndian.PutUint16(b[6:8], 0) // flags+fragoff (DF=0, no frag)
	b[8] = 64                             // TTL
	b[9] = proto
	binary.BigEndian.PutUint16(b[10:12], 0) // checksum slot

	// Addresses (we know they're v4 — caller guarantees).
	srcB := src.As4()
	copy(b[12:16], srcB[:])
	dstB := dst.As4()
	copy(b[16:20], dstB[:])

	// Header checksum over b[0:20].
	binary.BigEndian.PutUint16(b[10:12], checksum1071(b[:ipv4MinHeader], 0))
}

// buildTCP writes a 20-byte TCP header into b[0:20] and computes the
// TCP+pseudo-header checksum over b[0:end] where end is the total
// (header+payload) byte count.
func buildTCP(b []byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, window uint16,
	srcIP, dstIP netip.Addr, end int) {
	_ = b[tcpMinHeader-1]
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = 5 << 4 // dataOff=5 (no opts)
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], window)
	binary.BigEndian.PutUint16(b[16:18], 0) // checksum
	binary.BigEndian.PutUint16(b[18:20], 0) // urgent ptr

	// TCP checksum: sum of (pseudo-header + tcp-header + payload).
	// Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcpLen(2)
	srcB := srcIP.As4()
	dstB := dstIP.As4()
	var pseudo [12]byte
	copy(pseudo[0:4], srcB[:])
	copy(pseudo[4:8], dstB[:])
	pseudo[8] = 0
	pseudo[9] = protoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(end))

	sum := checksum1071Init(pseudo[:], 0)
	sum = checksum1071Init(b[:end], sum)
	binary.BigEndian.PutUint16(b[16:18], finalize1071(sum))
}

// buildUDP writes an 8-byte UDP header into b[0:8] and computes the
// UDP+pseudo-header checksum over b[0:end] where end = 8+payload_len.
func buildUDP(b []byte, srcPort, dstPort uint16, srcIP, dstIP netip.Addr, end int) {
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(end))
	binary.BigEndian.PutUint16(b[6:8], 0)

	srcB := srcIP.As4()
	dstB := dstIP.As4()
	var pseudo [12]byte
	copy(pseudo[0:4], srcB[:])
	copy(pseudo[4:8], dstB[:])
	pseudo[8] = 0
	pseudo[9] = protoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(end))

	sum := checksum1071Init(pseudo[:], 0)
	sum = checksum1071Init(b[:end], sum)
	cs := finalize1071(sum)
	if cs == 0 {
		// UDP convention: 0 means "no checksum"; replace with 0xFFFF so
		// receivers don't think we elided.
		cs = 0xFFFF
	}
	binary.BigEndian.PutUint16(b[6:8], cs)
}

// checksum1071 is the standard 16-bit one's complement sum (RFC 1071)
// with `seed` carried in. Pads odd-length inputs with a trailing zero.
func checksum1071(b []byte, seed uint32) uint16 {
	return finalize1071(checksum1071Init(b, seed))
}

func checksum1071Init(b []byte, seed uint32) uint32 {
	sum := seed
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)&1 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func finalize1071(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
