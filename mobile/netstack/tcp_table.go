//go:build netstack_real

package netstack

import (
	"net/netip"
	"sync"
)

// fivetuple uniquely identifies a TCP or UDP flow at the iOS-side end.
// (src, dst) here means (iOS-app-side, real-server-side). 24 bytes,
// comparable, suitable for map keys without alloc.
type fivetuple struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// MaxFlows caps the number of simultaneous TCP flows. New flows beyond
// this are RST'd. iOS apps see "connection refused" and retry.
//
// Why 128 and not unlimited:
//   - Each flow holds 4 KiB rxring + ~1 KiB state = ~5 KiB.
//   - 128 × 5 KiB = 640 KiB worst case for the table itself.
//   - Plus 2 goroutines per flow × ~4 KiB stack = ~1 MiB.
//   - Total at saturation: ~1.6 MiB shim for TCP at 128 flows.
//   - Room enough for Safari (~30 streams) + YouTube (~20) + Roblox (~8)
//     + speedtest (~32) ≈ 90 active. 128 leaves 30% buffer.
//
// hev's `max-session-count: 1200` analog. Ours is tighter because we're
// more memory-constrained on iOS NE.
const MaxTCPFlows = 128

// tcpTable maps 5-tuple → *tcpFlow with bounded capacity.
type tcpTable struct {
	mu    sync.Mutex
	flows map[fivetuple]*tcpFlow
}

func newTCPTable() *tcpTable {
	return &tcpTable{
		flows: make(map[fivetuple]*tcpFlow, MaxTCPFlows),
	}
}

// lookup returns the existing flow, or nil.
func (t *tcpTable) lookup(tup fivetuple) *tcpFlow {
	t.mu.Lock()
	f := t.flows[tup]
	t.mu.Unlock()
	return f
}

// insert installs a new flow. Returns false if at MaxTCPFlows capacity
// (caller should reset() or RST the iOS-side).
func (t *tcpTable) insert(tup fivetuple, f *tcpFlow) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.flows) >= MaxTCPFlows {
		return false
	}
	t.flows[tup] = f
	return true
}

func (t *tcpTable) remove(tup fivetuple) {
	t.mu.Lock()
	delete(t.flows, tup)
	t.mu.Unlock()
}

// snapshot copies the flow slice for iteration outside the lock
// (for reaping idle flows).
func (t *tcpTable) snapshot() []*tcpFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*tcpFlow, 0, len(t.flows))
	for _, f := range t.flows {
		out = append(out, f)
	}
	return out
}

func (t *tcpTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// closeAll is called on tunnel teardown.
func (t *tcpTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for tup, f := range t.flows {
		f.shutdown()
		delete(t.flows, tup)
	}
}
