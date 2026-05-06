//go:build !netstack_real

package netstack

import (
	"context"
	"errors"
)

// Stub implementations for builds without the netstack_real tag. The
// real Path 5 implementation lives behind `//go:build netstack_real`
// (tunnel.go + tcp_*.go + udp_nat.go + ipv4.go + bind_workaround_ios.go).
// When the tag is missing these stubs satisfy the netstack.go package-
// internal references so the package still compiles for unit-testing
// and for builds without the tag.
//
// IPA-C2 dropped the `ios` build tag from the implementation files
// because gomobile bind for iOS targets does NOT reliably set the
// "ios" build tag depending on Go version + gomobile version combo.
// IPA-C1 shipped with `//go:build ios && netstack_real` and the iOS
// build apparently linked the stub instead of the real impl —
// log showed go.inuse stuck at 1.1 MB throughout the session, no
// tamizdat allocations. With just `netstack_real` the impl is
// always linked when -tags=netstack_real is passed, regardless of
// the GOOS / build-tag combo gomobile sets.
//
// At runtime, Start() returns an error like "netstack disabled" so
// any caller knows the tunnel is unavailable in this build flavor.

func startTunnel(ctx context.Context, fd int32, configBlob string) error {
	_, _, _ = ctx, fd, configBlob
	return errors.New("netstack disabled (built without netstack_real tag)")
}

func stopTunnel() {}
