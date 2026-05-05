//go:build !netstack_real

package netstack

import (
	"context"
	"errors"
)

// Stub implementations of bridgeStart/bridgeStop for builds without
// the netstack_real tag. These let netstack.go compile (and the
// package's unit-testable bits run) when sing-tun + the rest of
// Phase 1 wiring isn't pulled in.
//
// When -tags=netstack_real is set, bridge.go's real implementations
// take over (the build-tag dispatch is exclusive — see the //go:build
// directives at the top of each file).

func bridgeStart(ctx context.Context, fd int32, configBlob string) error {
	_, _, _ = ctx, fd, configBlob
	return errors.New("netstack disabled (built without -tags=netstack_real)")
}

func bridgeStop() {}

// rtLog has a stub here too because handler.go/bridge.go reference it
// from netstack_real-tagged files; the real rtLog lives in rtlog.go
// (always-built). This stub is unused when handler/bridge are out of
// the build, but keeps `go build ./netstack` green for bisecting.
var _ = func() { rtLog("") }
