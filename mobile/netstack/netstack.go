// Package netstack is the Path 4 entry point — a single-process iOS
// extension data path using sing-tun + sagernet/gvisor in place of
// the IPA-Z series' "hev + SOCKS5 loopback" architecture.
//
// On startup, the iOS Network Extension hands us the utun fd and
// configBlob via Start(fd, configBlob). sing-tun's gvisor stack reads
// packets directly from the fd into its TCP/UDP demuxers; our Handler
// (handler.go) bridges each accepted flow to tamizdat.Client.DialContext
// (TCP) or .DialUDP (UDP) and pumps bytes between gvisor and tamizdat.
//
// The hev xcframework, the SOCKS5 loopback (mobile/socksstub), and the
// Swift PacketBridge (deleted in IPA-A1) all become unnecessary.
//
// Build tags:
//   - default: Start returns "netstack disabled" — the package compiles
//     for unit-testing the parser/state but cannot drive a tunnel.
//   - -tags=netstack_real: bridge.go + handler.go + dial_cap.go are
//     linked. Requires -tags=with_gvisor too (sing-tun's gvisor stack
//     is itself behind that tag — see with_gvisor_required.go for the
//     compile-time guard).
package netstack

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"
)

// runtime is package-global state for the singleton netstack instance.
// On iOS we run exactly one VPN tunnel at a time; multiple-call
// patterns (Stop+Start in sequence) are supported but concurrent
// active stacks are not.
type runtime struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	fd     int32
}

var rt = &runtime{}

// Start hands the iOS-supplied utun fd and the user's config blob to
// the netstack engine. On success, packet I/O runs on internal
// goroutines and Start returns immediately. On failure all
// partially-constructed resources are torn down before return.
//
// configBlob is a samizdat:// or tamizdat:// URI parsed by
// mobile/internal/configparse — the same parser the main app's
// "Connect" button uses to validate the user's pasted URL.
//
// Memory budget: SetMemoryLimit(37 MB) is set before bridgeStart
// runs (75% of iOS NEPacketTunnelProvider's 50 MB jetsam cap, per
// sing-box-for-apple's empirical formula). The limit is a soft
// target for Go's GC — under sustained allocation it forces aggressive
// GC but does NOT bound RSS (mmap, gvisor pools, cgo all escape).
// Calibrate empirically against jetsam fires; drop to 30 MB if needed.
func Start(fd int32, configBlob string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.cancel != nil {
		return errors.New("netstack already started")
	}
	// Reject fd <= 0: sing-tun's tun.Options treats FileDescriptor == 0
	// as the "create / open utun device" sentinel on darwin (see
	// sing-tun@v0.8.9/tun_darwin.go:94-122). The iOS
	// NEPacketTunnelProvider hands us a real fd that is always > 0;
	// receiving 0 here means the bridge wired up wrong.
	if fd <= 0 {
		return errors.New("invalid utun fd")
	}

	// Set the limit BEFORE bridgeStart so the very first allocations
	// (TLS handshake bytes, x509 certs, h2 framer scratch) already
	// observe the cap. Re-applying it under runtime.mu also makes
	// double-Start a no-op for the limit setter.
	debug.SetMemoryLimit(37 * 1024 * 1024)

	ctx, cancel := context.WithCancel(context.Background())
	if err := bridgeStart(ctx, fd, configBlob); err != nil {
		cancel()
		return err
	}
	rt.cancel = cancel
	rt.fd = fd
	return nil
}

// Stop tears down the gvisor stack, closes flows, and releases the
// fd back to iOS for reclaim. Idempotent — a second Stop after the
// first is a no-op.
//
// Ordering of teardown is delegated to bridgeStop (defined in either
// bridge.go or bridge_stub.go depending on build tags) to keep this
// shim tag-agnostic. bridgeStop runs OUTSIDE the runtime mutex per
// hermes' Phase 0 review note — long-running close paths shouldn't
// serialize a future Start re-entry.
func Stop() {
	rt.mu.Lock()
	cancel := rt.cancel
	rt.cancel = nil
	rt.fd = 0
	rt.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	bridgeStop()
}

// Phase 0 carry: import-touches keeps sing-tun + sing in the
// `require` graph during go mod tidy even when this package's other
// files don't reference them (e.g. when netstack_real is not set).
var _ = importTouches
