// IPA-Z: live shape-mode + RTT exporters for the iOS main-screen lamp.
//
// Mirrors what the Windows-GUI client polls from /debug/vars in the
// tamizdat-tun-windows binary. Both surface the same underlying
// tamizdat.Client accessors:
//
//   - RealShapeMode()       — ground-truth wire shape of the bulk
//                             transport ("ShapeFull" / "ShapeLite").
//                             V1 lamp lights when this == "ShapeLite"
//                             (valve flipped). V2/V3 use it together
//                             with LiteAlive + Locked counts.
//   - LockedRealtimeCount() — RTP-stickylocked flows (proven
//                             realtime). V2/V3 lamp lights when >0.
//   - LiteTransportAlive()  — V2/V3 only: dedicated lite-class
//                             transport currently up (1) or not (0).
//                             V1 always returns 0 because it has no
//                             separate lite truba.
//   - ActiveRealtimeCount() — total live realtime flows incl. UDP
//                             default-promote noise; diagnostic only.
//   - rtt probe (lite/bulk p50, last sample, last shape)
//
// All getters are safe to call from Swift on the main UI thread —
// they do bounded atomic loads only, no mutex contention beyond the
// short rt.mu lock that guards rt.samizdatClient lifecycle.
//
// The Swift main screen polls these every ~500 ms via a Timer and
// renders a green/yellow lamp + RTT text under the connection status.

package socksstub

import "runtime"

// CurrentShapeMode returns the controller-intent shape: "ShapeFull",
// "ShapeLite", or "" if no client is built. Operator's intent —
// not necessarily what's already on the wire.
func CurrentShapeMode() string {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return ""
	}
	return c.ShapeMode()
}

// RealShapeMode returns the actual wire-shape of the bulk transport
// right now ("ShapeFull" / "ShapeLite" / ""). Ground truth — drives
// the V1 lamp.
func RealShapeMode() string {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return ""
	}
	return c.RealShapeMode()
}

// ActiveRealtimeFlows returns total live realtime-class flows
// (default-promoted UDP noise included). Diagnostic only.
func ActiveRealtimeFlows() int {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return 0
	}
	return c.ActiveRealtimeCount()
}

// LockedRealtimeFlows returns the RTP-stickylocked flow count
// (proven realtime). 0 means no proven realtime traffic.
func LockedRealtimeFlows() int32 {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return 0
	}
	return c.LockedRealtimeCount()
}

// LiteAlive returns 1 if the V2/V3 dedicated lite-class transport is
// currently up, else 0. V1 always returns 0 (single-truba design has
// no separate lite transport — the bulk truba is reshaped instead).
func LiteAlive() int32 {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return 0
	}
	return c.LiteTransportAlive()
}

// RTTLiteP50Ms returns the median RTT in milliseconds for samples
// taken while the wire was in ShapeLite. -1 if no samples yet.
func RTTLiteP50Ms() int64 {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return -1
	}
	return c.RTTProbeSnapshot().LiteP50Ms
}

// RTTBulkP50Ms returns the median RTT in milliseconds for samples
// taken while the wire was in ShapeFull. -1 if no samples yet.
func RTTBulkP50Ms() int64 {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return -1
	}
	return c.RTTProbeSnapshot().BulkP50Ms
}

// RTTLastMs returns the most-recent RTT sample in milliseconds,
// regardless of shape. -1 if no samples yet.
func RTTLastMs() int64 {
	rt.mu.Lock()
	c := rt.samizdatClient
	rt.mu.Unlock()
	if c == nil {
		return -1
	}
	return c.RTTProbeSnapshot().LastMs
}

// MemHeapInUseKB returns runtime.MemStats.HeapInuse in KB. This is the
// Go heap that's CURRENTLY holding allocated objects — the working
// set, not the high-water mark. IPA-Z6: surfaced in the Swift
// heartbeat alongside `os_proc_available_memory()` to disambiguate
// "Go is bloating" vs "non-Go state is bloating" before crashes.
func MemHeapInUseKB() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapInuse / 1024)
}

// MemHeapSysKB returns runtime.MemStats.HeapSys in KB — total heap
// memory obtained from OS (committed). HeapInuse <= HeapSys; the gap
// is what GC has freed but not yet returned to OS.
func MemHeapSysKB() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapSys / 1024)
}

// MemHeapReleasedKB returns runtime.MemStats.HeapReleased in KB —
// memory the scavenger has actually returned to the OS. If this lags
// HeapSys-HeapInuse, GOMEMLIMIT pacer is starving the scavenger.
func MemHeapReleasedKB() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapReleased / 1024)
}

// MemNumGC returns the count of completed GC cycles since process
// start. Tells you whether GC is even firing.
func MemNumGC() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.NumGC)
}
