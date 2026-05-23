package tamizdat

import (
	"net"
	"testing"
	"time"
)

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestMasqueradeRateLimiterReapsIdleBucketWithEmptyTokens(t *testing.T) {
	rl := newMasqueradeRateLimiter()
	defer rl.close()

	ip := "192.0.2.55"
	for i := 0; i < masqueradeBurstSize; i++ {
		if !rl.allow(ip) {
			t.Fatalf("request %d unexpectedly denied while draining burst", i+1)
		}
	}
	if rl.allow(ip) {
		t.Fatal("bucket should be empty after draining burst")
	}

	rl.mu.Lock()
	b := rl.buckets[ip]
	b.tokens = 0
	b.lastRefil = time.Now().Add(-masqueradeBucketTTL - time.Second)
	rl.mu.Unlock()

	rl.reapExpiredBuckets(time.Now())

	rl.mu.Lock()
	_, ok := rl.buckets[ip]
	rl.mu.Unlock()
	if ok {
		t.Fatal("idle bucket with empty tokens was not reaped after TTL")
	}
}

func TestMasqueradeRateLimiterIPv6Same64SharesBucket(t *testing.T) {
	addr1 := &net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:12:1111::1"), Port: 443}
	addr2 := &net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:12:2222::2"), Port: 443}
	key1 := extractRemoteIP(remoteAddrConn{remote: addr1})
	key2 := extractRemoteIP(remoteAddrConn{remote: addr2})

	if key1 != "2001:db8:abcd:12::/64" {
		t.Fatalf("IPv6 bucket key = %q, want /64 prefix", key1)
	}
	if key1 != key2 {
		t.Fatalf("same /64 produced different bucket keys: %q vs %q", key1, key2)
	}

	rl := newMasqueradeRateLimiter()
	defer rl.close()
	for i := 0; i < masqueradeBurstSize; i++ {
		if !rl.allow(key1) {
			t.Fatalf("request %d unexpectedly denied while draining shared IPv6 /64 bucket", i+1)
		}
	}
	if rl.allow(key2) {
		t.Fatal("second IPv6 in same /64 received a fresh bucket instead of sharing rate limit")
	}
}
