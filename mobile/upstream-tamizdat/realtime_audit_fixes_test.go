package tamizdat

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAuditFix1_TokenedOpenNoCrossAttribution verifies that two goroutines
// concurrently calling ClassifyOpenWithToken + OpenWithToken receive their
// own pending flow-state and never inherit a sibling's state. Audit #1.
func TestAuditFix1_TokenedOpenNoCrossAttribution(t *testing.T) {
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		LegacyPortPromote: true,
	})
	controller := newRealtimeControllerWithConfig(det, time.Second, time.Second)

	const goroutines = 32
	const iters = 50
	var wg sync.WaitGroup
	var mismatch atomic.Uint64

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(idx int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				// Alternate UDP-realtime (STUN port) vs TCP-bulk (HTTPS).
				var meta FlowMeta
				var wantClass TrafficClass
				if (idx+i)%2 == 0 {
					meta = NewFlowMeta("udp", "stun.example:3478")
					wantClass = TrafficRealtime
				} else {
					meta = NewFlowMeta("tcp", "example.com:443")
					wantClass = TrafficBulk
				}
				class, token := det.ClassifyOpenWithToken(meta)
				if class != wantClass {
					mismatch.Add(1)
					continue
				}
				flowID := controller.OpenWithToken(class, token)
				if flowID == 0 {
					mismatch.Add(1)
					continue
				}
				// Sanity: the bound flow exists in detector.
				det.mu.Lock()
				st := det.flows[flowID]
				det.mu.Unlock()
				if st == nil {
					mismatch.Add(1)
				}
				controller.Close(flowID)
			}
		}(g)
	}
	wg.Wait()
	if got := mismatch.Load(); got != 0 {
		t.Fatalf("token race produced %d mismatches", got)
	}

	// After full Close, pending map should be empty.
	det.mu.Lock()
	pendingLen := len(det.pendingByID)
	det.mu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("pendingByID not drained: %d", pendingLen)
	}
}

// TestAuditFix2_DetectorCloseStopsCleanupLoop verifies that Detector.Close
// signals the cleanupLoop goroutine to exit. Audit #2.
func TestAuditFix2_DetectorCloseStopsCleanupLoop(t *testing.T) {
	det := newRealtimeDetector()
	// setController triggers the cleanupLoop goroutine to spawn.
	_ = newRealtimeControllerWithConfig(det, time.Second, time.Second)

	// Close should idempotently close the stop chan.
	det.Close()
	select {
	case <-det.stop:
		// closed; good.
	case <-time.After(time.Second):
		t.Fatal("Detector.Close did not close stop channel")
	}
	// Idempotent: second Close must not panic.
	det.Close()
}

// TestAuditFix3_EndpointCacheBoundedBySweep verifies that sweepIdle drops
// expired endpoint cache entries and applies a hard cap on size. Audit #3.
func TestAuditFix3_EndpointCacheBoundedBySweep(t *testing.T) {
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		EndpointCacheTTL: 100 * time.Millisecond,
	})

	// Seed many distinct endpoints with old timestamps.
	old := time.Now().Add(-time.Hour)
	det.mu.Lock()
	for i := 0; i < 25; i++ {
		host := "old-host-" + string(rune('a'+i)) + ".example"
		det.rememberEndpointLocked(endpointInfo{host: host}, old)
	}
	det.mu.Unlock()
	if got := len(det.endpointByHost); got < 25 {
		t.Fatalf("seeded %d hosts, want 25", got)
	}
	det.sweepIdle(time.Now())
	det.mu.Lock()
	got := len(det.endpointByHost)
	det.mu.Unlock()
	if got != 0 {
		t.Fatalf("sweepIdle did not drop expired host entries: %d remain", got)
	}

	// Re-seed with fresh entries; sweep should retain them.
	now := time.Now()
	det.mu.Lock()
	for i := 0; i < 5; i++ {
		host := "fresh-" + string(rune('a'+i)) + ".example"
		det.rememberEndpointLocked(endpointInfo{host: host}, now)
	}
	det.mu.Unlock()
	det.sweepIdle(now)
	det.mu.Lock()
	got = len(det.endpointByHost)
	det.mu.Unlock()
	if got != 5 {
		t.Fatalf("fresh entries dropped by sweep: got %d, want 5", got)
	}
}

// TestAuditFix15_StickyLockRejectsForgedFirstByte verifies that the Plan B
// sticky-lock no longer fires on bulk traffic merely beginning with 0x80.
// Audit #15.
func TestAuditFix15_StickyLockRejectsForgedFirstByte(t *testing.T) {
	det := newRealtimeDetector()
	st := &flowState{
		openTimeNS:  time.Now().UnixNano(),
		lastInterNS: time.Now().UnixNano(),
		state:       flowStateProvisionalRT,
		proto:       protoUDP,
	}
	// Forged packet: 0x80 first byte but length < 12, no RTP version/PT/seq.
	// Previously the single-byte 0x80 check would fire the lockin.
	det.mu.Lock()
	det.applyPlanBRTPStickyLockLocked(st, []byte{0x80, 0x01, 0x02, 0x03, 0x04, 0x05})
	det.mu.Unlock()
	if st.flags&flagLiteLocked != 0 {
		t.Fatal("sticky lock fired on too-short forged 0x80 payload")
	}
	if det.planBLockins.Load() != 0 {
		t.Fatalf("planBLockins = %d after forged short 0x80, want 0", det.planBLockins.Load())
	}

	// Forged packet: 1500 bytes starting with 0x80 but invalid RTP PT.
	// payload type 35 is in the reserved 35..71 RTP range -> invalid.
	bulk := make([]byte, 1500)
	bulk[0] = 0x80
	bulk[1] = 35 // invalid PT (not <=34, not >=96)
	det.mu.Lock()
	det.applyPlanBRTPStickyLockLocked(st, bulk)
	det.mu.Unlock()
	if st.flags&flagLiteLocked != 0 {
		t.Fatal("sticky lock fired on long forged 0x80 with invalid PT")
	}

	// Genuine RTP candidate: 0x80, PT=0 (PCMU), 12 bytes minimum.
	rtp := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	det.mu.Lock()
	det.applyPlanBRTPStickyLockLocked(st, rtp)
	det.mu.Unlock()
	if st.flags&flagLiteLocked == 0 {
		t.Fatal("sticky lock did NOT fire on genuine RTP candidate")
	}
	if det.planBLockins.Load() != 1 {
		t.Fatalf("planBLockins = %d after genuine RTP, want 1", det.planBLockins.Load())
	}
}

// TestAuditFix11_RTDemoteAgeKnob verifies that the RTDemoteAge config knob
// drives the CONFIRMED_RT -> PROVISIONAL_BULK transition timing. Audit #11.
func TestAuditFix11_RTDemoteAgeKnob(t *testing.T) {
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		PromoteScore: 0.55,
		DemoteScore:  0.25,
		WatchScore:   0.30,
		RTDemoteAge:  100 * time.Millisecond,
	})
	if got := det.cfg.RTDemoteAge; got != 100*time.Millisecond {
		t.Fatalf("RTDemoteAge = %v, want 100ms", got)
	}

	// Construct a CONFIRMED_RT flow with a low score and age > the knob.
	now := time.Now()
	st := &flowState{
		openTimeNS:  now.Add(-200 * time.Millisecond).UnixNano(),
		lastInterNS: now.Add(-200 * time.Millisecond).UnixNano(),
		confirmedNS: now.Add(-200 * time.Millisecond).UnixNano(),
		state:       flowStateConfirmedRT,
		proto:       protoUDP,
		scoreT3:     -10, // forces low totalScore
	}
	det.transitionState(st, now)
	if st.state != flowStateProvisionalBulk {
		t.Fatalf("flow at age 200ms with low score should demote (RTDemoteAge=100ms), got state=%d", st.state)
	}

	// Same flow but age < the knob: must NOT demote.
	det2 := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		PromoteScore: 0.55,
		DemoteScore:  0.25,
		WatchScore:   0.30,
		RTDemoteAge:  10 * time.Second,
	})
	st2 := &flowState{
		openTimeNS:  now.Add(-200 * time.Millisecond).UnixNano(),
		lastInterNS: now.Add(-200 * time.Millisecond).UnixNano(),
		confirmedNS: now.Add(-200 * time.Millisecond).UnixNano(),
		state:       flowStateConfirmedRT,
		proto:       protoUDP,
		scoreT3:     -10,
	}
	det2.transitionState(st2, now)
	if st2.state != flowStateConfirmedRT {
		t.Fatalf("flow at age 200ms with RTDemoteAge=10s should remain confirmedRT, got state=%d", st2.state)
	}
}
