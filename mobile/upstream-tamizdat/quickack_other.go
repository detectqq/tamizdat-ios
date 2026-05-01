//go:build !linux

package tamizdat

import "net"

// setAcceptedConnDelayedAck is Linux-only; non-Linux developer builds silently
// skip TCP_QUICKACK.
func setAcceptedConnDelayedAck(conn net.Conn) error {
	return nil
}
