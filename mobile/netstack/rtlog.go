package netstack

import (
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
