// IPA-V: per-flow process attribution.
//
// The iOS extension's Swift side can read NEFlowMetaData via
// packetFlow.readPacketsAndMetadata; metadata.sourceAppSigningIdentifier
// gives a string like "TEAMID.com.AnyDesk.AnyDesk". For each new TCP/UDP
// flow Swift extracts the destination 5-tuple plus the lowercased
// bundle-id and calls SubmitAppHint() before hev opens the SOCKS5
// CONNECT to us. By the time our handleConnect / handleUDPAssociate
// runs, the destination is already in the table and we can wrap the
// dial context with tamizdat.ContextWithAppHint(...) so the H2 CONNECT
// carries a Tamizdat-App-Hint header.
//
// Lookup is per (proto, dest) pair, where dest is the same
// "host:port" string the SOCKS5 client passed in. SOCKS5 may carry the
// destination as an IP literal or a domain — Swift always sees the
// post-DNS IP from the IP packet header, so iOS will be IP-only. We
// store both forms (raw IP-only, plus any pending domain-form fallback
// from a parallel resolver if we wire one later); for now IP-only is
// good enough since hev hands us the resolved destination IP, never a
// hostname.
//
// Map is short-lived (TTL on each entry, default 5s — flow setup is
// near-instant). Entries are pruned lazily on lookup + by a small
// background goroutine so a wedged Swift→Go call path can't leak
// memory.

package socksstub

import (
	"strings"
	"sync"
	"time"
)

type apphintEntry struct {
	hint      string
	expiresAt time.Time
}

type apphintTable struct {
	mu      sync.Mutex
	entries map[string]apphintEntry
}

var hintTable = &apphintTable{entries: map[string]apphintEntry{}}

// hintKey normalises the (network, dest) tuple into the lookup key.
// Same canonicalisation must be applied on both put and get sides.
func hintKey(network, dest string) string {
	return strings.ToLower(network) + ":" + dest
}

// SubmitAppHint records a process-attribution hint for an upcoming
// flow. Swift calls this from its packetFlow.readPacketsAndMetadata
// loop the moment it sees a TCP SYN / first UDP datagram with a
// non-empty NEFlowMetaData.sourceAppSigningIdentifier.
//
//   - proto:   "tcp" or "udp" (lowercased internally)
//   - dest:    "host:port" exactly as SOCKS5 will see it. For iOS this
//              is always an IP literal because hev resolves before SOCKS5.
//   - hint:    lowercased bundle-id (Swift strips the team-id prefix
//              before calling). Empty string is allowed and treated
//              as "drop any pending entry" (delete-on-empty).
//   - ttlMs:   how long the hint stays valid. Default 5000 if 0.
//
// Idempotent — subsequent calls overwrite. The TTL is reset on each
// call so resends from Swift just refresh the entry.
func SubmitAppHint(proto, dest, hint string, ttlMs int) {
	if proto == "" || dest == "" {
		return
	}
	key := hintKey(proto, dest)
	if hint == "" {
		hintTable.mu.Lock()
		delete(hintTable.entries, key)
		hintTable.mu.Unlock()
		return
	}
	if ttlMs <= 0 {
		ttlMs = 5000
	}
	hintTable.mu.Lock()
	hintTable.entries[key] = apphintEntry{
		hint:      strings.ToLower(strings.TrimSpace(hint)),
		expiresAt: time.Now().Add(time.Duration(ttlMs) * time.Millisecond),
	}
	hintTable.mu.Unlock()
}

// AppHintCount returns the current number of live hint entries (after
// pruning expired ones). For diagnostics only — exported so the Swift
// side can include it in a heartbeat log line.
func AppHintCount() int {
	now := time.Now()
	hintTable.mu.Lock()
	defer hintTable.mu.Unlock()
	for k, e := range hintTable.entries {
		if now.After(e.expiresAt) {
			delete(hintTable.entries, k)
		}
	}
	return len(hintTable.entries)
}

// lookupAppHint returns the recorded hint for (network, dest), or "" if
// none is present or the entry has expired. The entry is removed on
// successful lookup — a hint applies to a single flow only; if multiple
// flows to the same destination exist concurrently we'd risk attaching
// the wrong app's hint, but that's vastly less likely than the more
// common case of one app + one flow + one hint, and the worst case is
// a stale hint pointing at the wrong (still-realtime) classification.
//
// Called by dialUpstream / dialUpstreamUDP on each new SOCKS5 dial.
func lookupAppHint(network, dest string) string {
	key := hintKey(network, dest)
	now := time.Now()
	hintTable.mu.Lock()
	defer hintTable.mu.Unlock()
	e, ok := hintTable.entries[key]
	if !ok {
		return ""
	}
	if now.After(e.expiresAt) {
		delete(hintTable.entries, key)
		return ""
	}
	delete(hintTable.entries, key)
	return e.hint
}

// gcAppHintsLoop periodically prunes expired entries. Started once at
// package init. Cheap: holds the mutex briefly every 30s.
func init() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			hintTable.mu.Lock()
			for k, e := range hintTable.entries {
				if now.After(e.expiresAt) {
					delete(hintTable.entries, k)
				}
			}
			hintTable.mu.Unlock()
		}
	}()
}
