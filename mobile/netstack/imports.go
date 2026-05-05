// Phase 0 import-touches file. Pulls sing-tun + sing into the import
// graph so `go mod tidy` keeps them in `require`. Phase 1 replaces
// these with real wiring in handler.go / bridge.go.
package netstack

import (
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// importTouches takes a reference to a type from each dep so the
// compiler doesn't elide the import. Returns nil; never called.
func importTouches() any {
	var (
		_ tun.Tun
		_ tun.Stack
		_ M.Socksaddr
		_ N.PacketConn
	)
	return nil
}
