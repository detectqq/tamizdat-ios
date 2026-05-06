//go:build !ios || !netstack_real

package netstack

import (
	"context"
	"errors"
)

// Stub implementations for non-iOS or no-netstack_real builds. The
// real Path 5 implementation lives behind `//go:build ios &&
// netstack_real` (tunnel.go + tcp_*.go + udp_nat.go + ipv4.go +
// bind_workaround_ios.go). When either tag is missing, these stubs
// satisfy the netstack.go package-internal references so the package
// still compiles for unit-testing and for non-iOS gomobile binds.
//
// At runtime, Start() returns an error like "netstack disabled" so
// any caller knows the tunnel is unavailable in this build flavor.

func startTunnel(ctx context.Context, fd int32, configBlob string) error {
	_, _, _ = ctx, fd, configBlob
	return errors.New("netstack disabled (built without ios+netstack_real tags)")
}

func stopTunnel() {}
