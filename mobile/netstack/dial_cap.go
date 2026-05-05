//go:build netstack_real

package netstack

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// dialSem caps parallel outbound dials across both TCP and UDP handler
// paths. Without this, a Speedtest plus parallel iOS DNS resolutions
// can fan out to 200-500 simultaneous H2 stream openings, which (a)
// blows past tamizdat's per-conn stream limit and triggers a TLS
// handshake storm to spin up new transports, and (b) explodes
// goroutine count from baseline ~250 to 800+ in 10 s — well past the
// iOS extension's RAM budget. 48 is the deliberately conservative
// ceiling that survived production from IPA-Z onward; any dial that
// sees the channel full just drops the request rather than queueing
// behind a slow handshake.
//
// Phase 1 ports this verbatim from the deleted mobile/samizdat code
// path — both the channel and the drop-throttling logic.
var dialSem = make(chan struct{}, 48)

var (
	dialDropCount   int
	dialDropLastLog time.Time
	dialDropMu      sync.Mutex
)

// acquireDial blocks until a slot is free or the context cancels.
// Returns (release, true) on success, (nil, false) on context cancel
// or channel-full. Callers should bail without dialing on false.
func acquireDial(ctx context.Context) (func(), bool) {
	select {
	case dialSem <- struct{}{}:
		return func() { <-dialSem }, true
	case <-ctx.Done():
		return nil, false
	default:
		// Channel full. Don't queue — the iOS app will retry naturally
		// (DNS resolvers, TCP SYN-retransmits) and we want to shed load
		// rather than build a goroutine queue.
		dialDropMu.Lock()
		first := dialDropCount == 0
		dialDropCount++
		throttled := !first && time.Since(dialDropLastLog) < 5*time.Second
		if !throttled {
			dialDropLastLog = time.Now()
		}
		count := dialDropCount
		dialDropMu.Unlock()
		if !throttled {
			rtLog(fmt.Sprintf("warn: dial-cap reached, dropping (in_flight=48, total_drops=%d)", count))
		}
		return nil, false
	}
}
