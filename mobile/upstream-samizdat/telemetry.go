package samizdat

import (
	"expvar"
	"sync"
	"sync/atomic"
)

// Telemetry counters published via expvar (gated by ServerConfig.Debug).
//
// These give operators visibility into auth/masquerade/tunnel health without
// touching destinations or other PII (logs are still gated separately under
// s.logf). The bytes-per-flow histogram exists specifically to detect TSPU
// detector #490 enforcement: if many TCP flows terminate clustered around
// 15-20 KB it's the signature of policing kicking in.
//
// All vars are package-level so they're shared across all servers in the
// process (same as replay_guard expvars). Initialisation is one-shot via
// telemetryInitOnce to avoid expvar.Publish duplicate panics in tests.

var telemetryInitOnce sync.Once

// Counters
var (
	connectTotal       *expvar.Int
	connectAuthOK      *expvar.Int
	connectAuthFail    *expvar.Int
	connectReplay      *expvar.Int
	connectMasquerade  *expvar.Int
	masqRateLimited    *expvar.Int

	tunnelsTCPOpened   *expvar.Int
	tunnelsTCPClosed   *expvar.Int
	tunnelsUDPOpened   *expvar.Int
	tunnelsUDPClosed   *expvar.Int

	ssrfRejectedTCP    *expvar.Int
	ssrfRejectedUDP    *expvar.Int

	bytesClientToTarget atomic.Int64
	bytesTargetToClient atomic.Int64

	masqueradeBytesForwarded atomic.Int64

	// Bytes-per-flow buckets — at flow close we attribute the total bytes
	// transferred to one bucket. Distribution shape reveals #490: a heavy
	// spike in the 12-20 KB bucket = throttling enforcement.
	bytesPerFlowSub5KB    *expvar.Int
	bytesPerFlow5_15KB    *expvar.Int
	bytesPerFlow15_50KB   *expvar.Int
	bytesPerFlow50KB_1MB  *expvar.Int
	bytesPerFlowAbove1MB  *expvar.Int

	// Handshake duration sum + count (avg = sum/count).
	handshakeDurationNanosSum   atomic.Int64
	handshakeDurationNanosCount atomic.Int64
)

func initTelemetry() {
	telemetryInitOnce.Do(func() {
		connectTotal = newPublishedInt("samizdat.connect.total")
		connectAuthOK = newPublishedInt("samizdat.connect.auth_ok")
		connectAuthFail = newPublishedInt("samizdat.connect.auth_fail")
		connectReplay = newPublishedInt("samizdat.connect.replay_rejected")
		connectMasquerade = newPublishedInt("samizdat.connect.masquerade_dispatched")
		masqRateLimited = newPublishedInt("samizdat.masquerade.rate_limited")

		tunnelsTCPOpened = newPublishedInt("samizdat.tunnels.tcp.opened")
		tunnelsTCPClosed = newPublishedInt("samizdat.tunnels.tcp.closed")
		tunnelsUDPOpened = newPublishedInt("samizdat.tunnels.udp.opened")
		tunnelsUDPClosed = newPublishedInt("samizdat.tunnels.udp.closed")

		ssrfRejectedTCP = newPublishedInt("samizdat.ssrf.rejected_tcp")
		ssrfRejectedUDP = newPublishedInt("samizdat.ssrf.rejected_udp")

		expvar.Publish("samizdat.bytes.client_to_target", expvar.Func(func() any {
			return bytesClientToTarget.Load()
		}))
		expvar.Publish("samizdat.bytes.target_to_client", expvar.Func(func() any {
			return bytesTargetToClient.Load()
		}))
		expvar.Publish("samizdat.masquerade.bytes_forwarded", expvar.Func(func() any {
			return masqueradeBytesForwarded.Load()
		}))

		bytesPerFlowSub5KB = newPublishedInt("samizdat.bytes_per_flow.sub_5kb")
		bytesPerFlow5_15KB = newPublishedInt("samizdat.bytes_per_flow.5_15kb")
		bytesPerFlow15_50KB = newPublishedInt("samizdat.bytes_per_flow.15_50kb")
		bytesPerFlow50KB_1MB = newPublishedInt("samizdat.bytes_per_flow.50kb_1mb")
		bytesPerFlowAbove1MB = newPublishedInt("samizdat.bytes_per_flow.above_1mb")

		expvar.Publish("samizdat.handshake.duration_nanos_sum", expvar.Func(func() any {
			return handshakeDurationNanosSum.Load()
		}))
		expvar.Publish("samizdat.handshake.duration_nanos_count", expvar.Func(func() any {
			return handshakeDurationNanosCount.Load()
		}))
	})
}

func newPublishedInt(name string) *expvar.Int {
	v := new(expvar.Int)
	expvar.Publish(name, v)
	return v
}

// observeFlowBytes attributes a closed flow's total bytes to its bucket.
// Called from handler shutdown paths (TCP CONNECT defaultConnHandler /
// proxyHandler, UDP server pump, etc.).
func observeFlowBytes(n int64) {
	switch {
	case n < 5*1024:
		if bytesPerFlowSub5KB != nil {
			bytesPerFlowSub5KB.Add(1)
		}
	case n < 15*1024:
		if bytesPerFlow5_15KB != nil {
			bytesPerFlow5_15KB.Add(1)
		}
	case n < 50*1024:
		if bytesPerFlow15_50KB != nil {
			bytesPerFlow15_50KB.Add(1)
		}
	case n < 1024*1024:
		if bytesPerFlow50KB_1MB != nil {
			bytesPerFlow50KB_1MB.Add(1)
		}
	default:
		if bytesPerFlowAbove1MB != nil {
			bytesPerFlowAbove1MB.Add(1)
		}
	}
}

// safeIntAdd is a nil-safe helper -- counters may be nil if telemetry never
// initialised (e.g. Debug=false). All callers should be no-ops in that case.
func safeIntAdd(c *expvar.Int, delta int64) {
	if c != nil {
		c.Add(delta)
	}
}
