//go:build netstack_real

package netstack

import (
	"context"
	"fmt"
	goruntime "runtime"
	"runtime/debug"
	"time"
)

// memwatchInterval is how often the watchdog checks runtime.MemStats.
// 5 s matches sing-box-for-apple's oomkiller adaptiveTimer cadence
// (`service/oomkiller/timer.go:39`). Faster (~1 s) burns CPU on
// ReadMemStats stop-the-world pauses; slower (~10 s) misses transient
// spikes during Roblox-style connection storms.
const memwatchInterval = 5 * time.Second

// memwatchHighWatermarkSys is the runtime.MemStats.Sys threshold above
// which we eagerly call debug.FreeOSMemory(). 45 MiB leaves ~5 MiB
// safety margin under the iOS NEPacketTunnelProvider 50 MiB jetsam
// cap. sing-box-for-apple's oomkiller uses an adaptive threshold but
// fires at roughly the same point in practice.
//
// Sys here = total bytes of memory obtained from the OS by Go's
// runtime, including heap arenas + stack arenas + mmap'd code/data.
// FreeOSMemory walks the heap and madvise(MADV_FREE)s pages back to
// the OS. iOS's jetsam decision uses physical_footprint which counts
// dirty pages; pages MADV_FREE'd are treated as reclaimable and
// don't count.
const memwatchHighWatermarkSys uint64 = 45 * 1024 * 1024

// startMemWatch runs the FreeOSMemory watchdog goroutine for the
// lifetime of `ctx`. Should be called once per netstack.Start.
//
// Why this matters: Go's GC runs FreeOSMemory lazily — by default it
// can take 5+ minutes for unused arenas to be released to the OS.
// On iOS NE, that's far too slow: jetsam fires at 50 MB physical_footprint,
// and Go can have 10+ MB of MADV_FREE-eligible-but-not-yet-MADV_FREE'd
// pages sitting in our process. Without this watchdog, IPA-B1/B2
// crashed during sustained allocation spikes (Speedtest fanout +
// Roblox launch) because Go held memory the kernel could have
// reclaimed if asked. sing-box-for-apple's oomkiller calls FreeOSMemory
// on every poll while triggered (`service/oomkiller/timer.go:160,215`).
func startMemWatch(ctx context.Context) {
	go func() {
		t := time.NewTicker(memwatchInterval)
		defer t.Stop()

		var triggered bool
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				var ms goruntime.MemStats
				goruntime.ReadMemStats(&ms)

				if ms.Sys > memwatchHighWatermarkSys {
					if !triggered {
						rtLog(fmt.Sprintf(
							"warn: memwatch fired Sys=%dKB HeapInuse=%dKB HeapIdle=%dKB → FreeOSMemory()",
							ms.Sys/1024, ms.HeapInuse/1024, ms.HeapIdle/1024,
						))
					}
					triggered = true
					debug.FreeOSMemory()

					// Re-read AFTER FreeOSMemory to log the recovery
					// in the same line so the bridge tail can compare
					// before/after at a glance.
					goruntime.ReadMemStats(&ms)
					rtLog(fmt.Sprintf(
						"info: memwatch post-free Sys=%dKB HeapInuse=%dKB HeapReleased=%dKB",
						ms.Sys/1024, ms.HeapInuse/1024, ms.HeapReleased/1024,
					))
				} else if triggered {
					// Below threshold again — clear the latch so the
					// next breach gets logged as "fired" not silent.
					triggered = false
					rtLog(fmt.Sprintf(
						"info: memwatch back under watermark Sys=%dKB",
						ms.Sys/1024,
					))
				}
			}
		}
	}()
}
