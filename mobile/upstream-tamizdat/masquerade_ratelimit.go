package tamizdat

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Per-source-IP rate-limit on masquerade forward (compass v2 §3.11):
// without this, an attacker without PSK can flood the server with
// random ClientHellos -- each one ECDH+HKDF+HMAC-checked, fails auth,
// then the server opens a fresh TCP+TLS forward to ok.ru. Amplification
// factor: 1 attacker ClientHello -> 1 outbound TLS to cover origin.
// At 10 Gbps the attacker easily exhausts the server's upstream-bandwidth
// to ok.ru, AND can produce IP-reputation problems for the origin.
//
// Defense: simple token-bucket per source IP. Defaults: 30 forwards
// per minute per IP, burst 10. Most legitimate probes from a single
// scanner stay under this; sustained attack is starved.

const (
	masqueradeRatePerMin   = 30
	masqueradeBurstSize    = 10
	masqueradeBucketTTL    = 5 * time.Minute
	masqueradeReapInterval = 60 * time.Second
)

type masqueradeRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	stop    chan struct{}
}

type tokenBucket struct {
	tokens    float64
	lastRefil time.Time
	rate      float64 // tokens per second
	capacity  float64
}

func newMasqueradeRateLimiter() *masqueradeRateLimiter {
	rl := &masqueradeRateLimiter{
		buckets: make(map[string]*tokenBucket),
		stop:    make(chan struct{}),
	}
	go rl.reaper()
	return rl
}

// allow checks whether a forward from `ip` is allowed; consumes one token if yes.
// Returns false on rate-limit denial; the caller should then drop the connection
// without forwarding.
func (rl *masqueradeRateLimiter) allow(ip string) bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		b = &tokenBucket{
			tokens:    masqueradeBurstSize - 1, // first request consumes one
			lastRefil: now,
			rate:      float64(masqueradeRatePerMin) / 60.0,
			capacity:  masqueradeBurstSize,
		}
		rl.buckets[ip] = b
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastRefil).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastRefil = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// reaper periodically deletes idle buckets so the map doesn't grow without
// bound (probes from rotating bots).
func (rl *masqueradeRateLimiter) reaper() {
	t := time.NewTicker(masqueradeReapInterval)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-t.C:
			rl.reapExpiredBuckets(time.Now())
		}
	}
}

func (rl *masqueradeRateLimiter) reapExpiredBuckets(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, b := range rl.buckets {
		// If bucket has been idle longer than TTL, drop it. The previous
		// tokens-based check was unreachable because reaper never recomputes refill.
		if now.Sub(b.lastRefil) > masqueradeBucketTTL {
			delete(rl.buckets, ip)
		}
	}
}

func (rl *masqueradeRateLimiter) close() {
	close(rl.stop)
}

// extractRemoteIP pulls the IP portion of a net.Conn RemoteAddr() result.
// Falls back to the full string if SplitHostPort fails. IPv6 addresses are
// normalized to /64 prefixes so a single client allocation cannot create a fresh
// rate-limit bucket per 128-bit address; IPv4 remains per-host.
func extractRemoteIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if parsed.Is6() && !parsed.Is4In6() {
		if pfx, perr := parsed.Prefix(64); perr == nil {
			return pfx.Masked().String()
		}
	}
	return parsed.String()
}
