//go:build ios && netstack_real

package netstack

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	tamizdat "github.com/detectqq/tamizdat"
)

// iosBindDialer returns a tamizdat.DialFunc that binds outbound TCP
// connections to the given utun-side IP address. This is the
// "bind() workaround" Apple's DTS team Quinn ("the Eskimo") confirmed
// recovers ~3× TCP throughput from inside an iOS Network Extension
// when the remote server IP is included in the tunnel's routes
// (which it always is when full-tunnel default is set):
//   https://developer.apple.com/forums/thread/681516
//
// Verbatim from the thread: "if the remote host is 192.168.200.2 and
// our only included route is 192.168.200.2/32, upload performance is
// slow [~300 Mbps]. However, if we avoid the remote host's address...
// upload performance is fast [~950 Mbps]." The workaround: bind the
// local socket to the tun's own address before connect.
//
// Why iOS-only build tag: bind() to a specific local IP has
// undesirable side effects on other platforms (e.g., desktop Linux/
// macOS where it forces the kernel to pick the route, sometimes the
// wrong one). On iOS NE, full-tunnel is the only configuration we
// run, so the workaround is unconditionally a net positive.
//
// We bind only TCP (the workaround is documented for TCP; Apple says
// it has "undesirable behavioral effects on datagram sockets"). UDP
// dials go through tamizdat.DialUDP which uses an H2 stream over our
// already-bound TCP transport, so UDP doesn't need its own bind().
func iosBindDialer(utunIP netip.Addr) tamizdat.DialFunc {
	if !utunIP.IsValid() {
		return nil
	}
	tcpAddr := &net.TCPAddr{IP: utunIP.AsSlice()}
	d := &net.Dialer{
		LocalAddr: tcpAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			// Set SO_REUSEADDR so consecutive dials from the same
			// (utunIP:0) → same-server-IP don't trip TIME-WAIT
			// quirks on the iOS kernel side.
			var serr error
			err := c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// Only apply bind to TCP. UDP path through tamizdat.DialUDP
		// goes via the existing H2 transport, no separate dial.
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			// Fall back to default dialer for non-TCP. Keeps semantics
			// unchanged for unexpected callers.
			var bare net.Dialer
			return bare.DialContext(ctx, network, address)
		}
		return d.DialContext(ctx, network, address)
	}
}
