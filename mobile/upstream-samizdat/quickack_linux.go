//go:build linux

package samizdat

import (
	"net"

	"golang.org/x/sys/unix"
)

// setAcceptedConnDelayedAck enables TCP delayed ACK on server-side accepted
// client-facing TCP connections. TCP_QUICKACK=0 is the NDSS 2025 dMAP
// recommended mitigation: raise transport-layer RTT (TRTT) instead of adding
// userspace per-record jitter that inflates ARTT.
func setAcceptedConnDelayedAck(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 0)
	})
	if err != nil {
		return err
	}
	return setErr
}
