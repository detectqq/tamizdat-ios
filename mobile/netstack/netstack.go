// Package netstack is the Path 5 / Option A entry point — a single-
// process iOS extension data path that owns the utun fd directly,
// implements userspace TCP+UDP, and forwards every flow through the
// existing tamizdat.Client.
//
// History:
//   - IPA-A series (Path 3): hev-socks5-tunnel (C/lwIP) + SOCKS5 loopback
//     + mobile/socksstub. Hit memory ceiling under multi-app load.
//   - IPA-B series (Path 4): sing-tun + sagernet/gvisor. B1=gvisor mode
//     (30 Mbps cap from iOS-specific TCP buffer cap). B2=Mixed mode (TCP
//     NAT loopback broken on iOS NE). B3=full sing-box-for-apple parity
//     (Mixed worked but tamizdat V1 cap=150 saturated under iOS multi-
//     app burst). B4=V2 mode (cap=300 streams) + sync.Pool. B5=shrink
//     all per-flow buffers.
//   - IPA-C series (Path 5 / Option A): this package. Drops sing-tun +
//     sagernet/gvisor entirely; writes our own minimal TCP+UDP shim
//     tuned for iOS NE 50 MB jetsam cap. Per-flow ≤9 KiB (vs sing-tun
//     ~96 KiB), bounded MaxFlows=128, hot path zero-alloc steady state.
//     Architecture per Psiphon production playbook: tunnel IP packets,
//     not per-flow Go structs.
//
// On startup, the iOS Network Extension hands us the utun fd
// (already dup()ed in Swift per IPA-B1) plus the config blob. We open
// our own TCP/UDP machinery and dispatch packets directly to
// tamizdat.Client.DialContext (TCP) / .DialUDP (UDP).
//
// Build tags:
//   - default: Start returns "netstack disabled" — package compiles for
//     unit-testing the parser/state but cannot drive a tunnel.
//   - -tags=netstack_real: tunnel.go + tcp_*.go + udp_nat.go + ipv4.go +
//     bind_workaround_ios.go are linked. iOS-only path (//go:build ios
//     && netstack_real). Path 5 NO LONGER requires with_gvisor or
//     sing-tun.
package netstack

import (
	"context"
	"errors"
	"sync"
)

// netstackState is package-global state for the singleton netstack
// instance. On iOS we run exactly one VPN tunnel at a time; multiple-
// call patterns (Stop+Start in sequence) are supported but concurrent
// active stacks are not.
type netstackState struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	fd     int32
}

var rt = &netstackState{}

// Start hands the iOS-supplied utun fd and the user's config blob to
// the netstack engine. On success, packet I/O runs on internal
// goroutines and Start returns immediately. On failure all
// partially-constructed resources are torn down before return.
//
// configBlob is a samizdat:// or tamizdat:// URI parsed by
// mobile/internal/configparse — the same parser the main app's
// "Connect" button uses to validate the user's pasted URL.
//
// Memory limit + GC tuning is configured INSIDE startTunnel because
// it depends on the build (tunnel.go for Path 5, bridge.go for the
// older sing-tun-based code in case we keep parallel paths). See
// project_ios_singtun_ground_truth.md memory file for the
// 50 MB × 3/4 = 37.5 MB rationale.
func Start(fd int32, configBlob string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.cancel != nil {
		return errors.New("netstack already started")
	}
	if fd <= 0 {
		return errors.New("invalid utun fd")
	}

	// IPA-C2 diagnostic: log unconditionally before startTunnel so the
	// App Group log shows which build flavor is linked. With the new
	// build-tag scheme (just netstack_real, no ios), this should always
	// be the real Path 5 impl. Helps catch a future repeat of the C1
	// silent stub-link surprise.
	rtLogPretunnel(fd)

	ctx, cancel := context.WithCancel(context.Background())
	if err := startTunnel(ctx, fd, configBlob); err != nil {
		cancel()
		return err
	}
	rt.cancel = cancel
	rt.fd = fd
	return nil
}

// Stop tears down the netstack and closes flows. Idempotent.
//
// Ordering inside stopTunnel: cancel ctx → close flow tables → close
// tamizdat client → close fd (last, so any in-flight syscall.Read
// gets EBADF and exits the run loop cleanly).
func Stop() {
	rt.mu.Lock()
	cancel := rt.cancel
	rt.cancel = nil
	rt.fd = 0
	rt.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	stopTunnel()
}
