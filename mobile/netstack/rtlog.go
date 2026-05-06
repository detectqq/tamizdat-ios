package netstack

import (
	"fmt"

	"github.com/anarki/samizdat-ios/mobile/samizdat"
)

// rtLog mirrors a status line into the App Group log file owned by
// the samizdat package. The PacketTunnelProvider opened that file
// via samizdat.SetLogSink(...) before Start() was called, so any
// line emitted here lands in the same timeline as Swift-side logs
// and the bridge sees it on its tail.
//
// We deliberately route through samizdat.AddLog (not log.Printf)
// because the iOS extension has no terminal; without the App Group
// sink, gvisor / tamizdat error lines would vanish into the void.
func rtLog(line string) {
	samizdat.AddLog(line)
}

// rtLogPretunnel is the IPA-C2 diagnostic log called from
// netstack.Start BEFORE startTunnel runs. Build flavor is encoded
// in the log line so we can tell from a smoke-test log whether the
// real Path 5 impl or the stub was linked.
//
// IPA-C1 shipped with `//go:build ios && netstack_real` on impl
// files; iOS build apparently didn't set the "ios" tag and stub
// was linked silently. Stub returned error from startTunnel BUT
// for unknown reasons Swift didn't log the error path — leaving us
// blind. This Pretunnel log is the unconditional canary.
func rtLogPretunnel(fd int32) {
	samizdat.AddLog(fmt.Sprintf("info: netstack.Start fd=%d (build=%s)", fd, buildFlavor()))
}
