package tamizdat

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestRealtimeDetectorClassifyOpen(t *testing.T) {
	det := newRealtimeDetector()
	if got := det.ClassifyOpen(NewFlowMeta("udp", "stun.l.google.com:3478")); got != TrafficRealtime {
		t.Fatalf("STUN port class = %s, want realtime", got)
	}
	if got := det.ClassifyOpen(NewFlowMeta("tcp", "example.com:443")); got != TrafficBulk {
		t.Fatalf("HTTPS class = %s, want bulk", got)
	}

	stun := make([]byte, 20)
	stun[4], stun[5], stun[6], stun[7] = 0x21, 0x12, 0xa4, 0x42
	if got := det.ClassifyOpen(FlowMeta{Network: "udp", Address: "example.com:9999", Payload: stun}); got != TrafficRealtime {
		t.Fatalf("STUN magic class = %s, want realtime", got)
	}

	rtp := []byte{0x80, 0x60, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4}
	if got := det.ClassifyOpen(FlowMeta{Network: "udp", Address: "example.com:9999", Payload: rtp}); got != TrafficRealtime {
		t.Fatalf("RTP magic class = %s, want realtime", got)
	}
}

func TestRealtimeDetectorSmoothnessPromotesAfterThreeWindows(t *testing.T) {
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		RealtimePorts:           []int{3478},
		SmoothnessSamples:       3,
		SmoothnessWindows:       3,
		SmoothnessMaxJitterFrac: 0.10,
		SmoothnessMinInterval:   10 * time.Millisecond,
		SmoothnessMaxInterval:   30 * time.Millisecond,
	})
	base := time.Unix(100, 0)
	class := TrafficBulk
	for i := 0; i < 10; i++ {
		class = det.ObservePacket(42, base.Add(time.Duration(i)*20*time.Millisecond), []byte{0x01})
	}
	if class != TrafficRealtime {
		t.Fatalf("smooth flow class = %s, want realtime after 3 windows", class)
	}
}

func TestRealtimeTCPDoesNotPromoteOnSmoothBytes(t *testing.T) {
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		RealtimePorts:           []int{3478},
		SmoothnessSamples:       2,
		SmoothnessWindows:       2,
		SmoothnessMaxJitterFrac: 1.0,
		SmoothnessMinInterval:   time.Millisecond,
		SmoothnessMaxInterval:   50 * time.Millisecond,
	})
	controller := newRealtimeControllerWithConfig(det, time.Second, time.Second)
	flowID := controller.Open(TrafficBulk)

	local, peer := net.Pipe()
	conn := wrapRealtimeConn(local, controller, flowID)
	defer peer.Close()
	defer conn.Close()

	writeDone := make(chan error, 1)
	go func() {
		for i := 0; i < 6; i++ {
			if i > 0 {
				time.Sleep(5 * time.Millisecond)
			}
			if _, err := peer.Write([]byte{byte(i)}); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	buf := make([]byte, 1)
	for i := 0; i < 6; i++ {
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read smooth TCP byte %d: %v", i, err)
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write smooth TCP bytes: %v", err)
	}

	if got := controller.Mode(); got != ShapeFull {
		t.Fatalf("smooth TCP bytes promoted mode = %s, want full", got)
	}
	if got := controller.ActiveRealtimeCount(); got != 0 {
		t.Fatalf("active realtime after smooth TCP bytes = %d, want 0", got)
	}
}

func TestRealtimeControllerHysteresis(t *testing.T) {
	controller := newRealtimeControllerWithConfig(newRealtimeDetector(), 20*time.Millisecond, 20*time.Millisecond)
	flowID := controller.Open(TrafficRealtime)
	if got := controller.Mode(); got != ShapeLite {
		t.Fatalf("mode after realtime open = %s, want lite", got)
	}
	controller.Close(flowID)
	if got := controller.Mode(); got != ShapeLite {
		t.Fatalf("mode immediately after close = %s, want lite during hysteresis", got)
	}
	deadline := time.After(250 * time.Millisecond)
	for controller.Mode() != ShapeFull {
		select {
		case <-deadline:
			t.Fatal("mode did not return to full after hysteresis")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestRealtimeControllerPromoteBulkFlow(t *testing.T) {
	controller := newRealtimeControllerWithConfig(newRealtimeDetector(), 10*time.Millisecond, 10*time.Millisecond)
	flowID := controller.Open(TrafficBulk)
	if got := controller.Mode(); got != ShapeFull {
		t.Fatalf("mode after bulk open = %s, want full", got)
	}
	controller.Promote(flowID)
	if got := controller.Mode(); got != ShapeLite {
		t.Fatalf("mode after promote = %s, want lite", got)
	}
	if got := controller.ActiveRealtimeCount(); got != 1 {
		t.Fatalf("active realtime = %d, want 1", got)
	}
}

func TestRealtimeControllerOnModeReturnToFullCallback(t *testing.T) {
	controller := newRealtimeControllerWithConfig(newRealtimeDetector(), 10*time.Millisecond, 10*time.Millisecond)
	fired := make(chan struct{}, 2)
	controller.onModeReturnToFull = func() { fired <- struct{}{} }

	flowID := controller.Open(TrafficRealtime)
	controller.Close(flowID)
	select {
	case <-fired:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("onModeReturnToFull did not fire after hysteresis returned to full")
	}
	if got := controller.Mode(); got != ShapeFull {
		t.Fatalf("mode after callback = %s, want full", got)
	}
	select {
	case <-fired:
		t.Fatal("onModeReturnToFull fired more than once for one hysteresis timer")
	case <-time.After(20 * time.Millisecond):
	}

	flowID = controller.Open(TrafficRealtime)
	controller.Close(flowID)
	time.Sleep(2 * time.Millisecond)
	flowID2 := controller.Open(TrafficRealtime)
	select {
	case <-fired:
		t.Fatal("onModeReturnToFull fired even though realtime reopened during hysteresis")
	case <-time.After(40 * time.Millisecond):
	}
	controller.Close(flowID2)
}

func TestRealtimeDetectorAppHintPromotesNonRealtimePort(t *testing.T) {
	// Default config: pool of known-realtime app substrings + standard ports.
	det := newRealtimeDetector()

	// Sanity: TCP/443 to example.com normally classifies bulk.
	if got := det.ClassifyOpen(NewFlowMeta("tcp", "example.com:443")); got != TrafficBulk {
		t.Fatalf("baseline tcp/443 = %s, want bulk", got)
	}

	// With AppHint that matches a known realtime app substring,
	// the same destination is promoted to realtime.
	if got := det.ClassifyOpen(FlowMeta{
		Network: "tcp", Address: "example.com:443", AppHint: "anydesk-service",
	}); got != TrafficRealtime {
		t.Fatalf("anydesk-service hint on tcp/443 = %s, want realtime", got)
	}
	if got := det.ClassifyOpen(FlowMeta{
		Network: "tcp", Address: "example.com:443", AppHint: "Roblox.exe-via-Wine",
	}); got != TrafficRealtime {
		t.Fatalf("roblox hint = %s, want realtime", got)
	}

	// Unknown / browser hint must NOT promote: chrome/firefox multiplex many
	// flow types and false-positive realtime would weaken bulk shape.
	if got := det.ClassifyOpen(FlowMeta{
		Network: "tcp", Address: "example.com:443", AppHint: "chrome",
	}); got != TrafficBulk {
		t.Fatalf("chrome hint on tcp/443 = %s, want bulk", got)
	}
	if got := det.ClassifyOpen(FlowMeta{
		Network: "tcp", Address: "example.com:443", AppHint: "curl",
	}); got != TrafficBulk {
		t.Fatalf("curl hint on tcp/443 = %s, want bulk", got)
	}

	// Empty hint (non-Linux client / detection failed) must not promote.
	if got := det.ClassifyOpen(FlowMeta{
		Network: "tcp", Address: "example.com:443", AppHint: "",
	}); got != TrafficBulk {
		t.Fatalf("empty hint = %s, want bulk", got)
	}
}

func TestRealtimeDetectorAppHintExplicitEmptyDisables(t *testing.T) {
	// Operator can disable hint promotion by setting RealtimeAppHints=[]string{}
	// (vs leaving it nil which uses defaults).
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		RealtimePorts:    []int{3478},
		RealtimeAppHints: []string{},
	})
	if got := det.ClassifyOpen(FlowMeta{
		Network: "tcp", Address: "example.com:443", AppHint: "anydesk",
	}); got != TrafficBulk {
		t.Fatalf("hint with empty hints list = %s, want bulk", got)
	}
}

func TestPlanB_DefaultPromoteUDPNonDNS(t *testing.T) {
	det := newRealtimeDetector()

	if got := det.ClassifyOpen(NewFlowMeta("udp", "example.com:50000")); got != TrafficRealtime {
		t.Fatalf("UDP/50000 class = %s, want realtime", got)
	}
	if got := det.ClassifyOpen(NewFlowMeta("udp", "example.com:443")); got != TrafficRealtime {
		t.Fatalf("UDP/443 class = %s, want realtime", got)
	}
	if got := det.ClassifyOpen(NewFlowMeta("tcp", "example.com:443")); got != TrafficBulk {
		t.Fatalf("TCP/443 class = %s, want bulk", got)
	}
	if got := det.PlanBStats().Promotes; got < 2 {
		t.Fatalf("PlanB promotes = %d, want >= 2", got)
	}
}

func TestPlanB_DNSAndDoTExcluded(t *testing.T) {
	det := newRealtimeDetector()

	if got := det.ClassifyOpen(NewFlowMeta("udp", "resolver.example:53")); got != TrafficBulk {
		t.Fatalf("UDP/53 class = %s, want bulk", got)
	}
	if got := det.ClassifyOpen(NewFlowMeta("udp", "resolver.example:853")); got != TrafficBulk {
		t.Fatalf("UDP/853 class = %s, want bulk", got)
	}
}

func TestPlanB_RTPStickyLockSurvivesBulkBlast(t *testing.T) {
	det := newRealtimeDetector()
	controller := newRealtimeControllerWithConfig(det, time.Second, time.Second)
	class := det.ClassifyOpen(NewFlowMeta("udp", "voice.example:50000"))
	flowID := controller.Open(class)
	base := time.Unix(330, 0)

	if got := det.Observe(ObservedPacket{FlowID: flowID, At: base, Payload: testRTPPayload(1, 0x01020304), Size: 80, Direction: DirOutbound}); got != TrafficRealtime {
		t.Fatalf("first RTP observe class = %s, want realtime", got)
	}
	bulk := make([]byte, 512*1024)
	for i := 0; i < 20; i++ { // 10 MiB over 500 ms: well above the non-RTP cap.
		at := base.Add(time.Duration(i+1) * 25 * time.Millisecond)
		if got := det.Observe(ObservedPacket{FlowID: flowID, At: at, Payload: bulk, Size: len(bulk), Direction: DirOutbound}); got != TrafficRealtime {
			t.Fatalf("bulk blast observe %d class = %s, want realtime", i, got)
		}
	}
	stats := det.PlanBStats()
	if stats.Demotes != 0 {
		t.Fatalf("PlanB demotes = %d, want 0", stats.Demotes)
	}
	if stats.Lockins != 1 {
		t.Fatalf("PlanB lockins = %d, want 1", stats.Lockins)
	}
}

func TestPlanB_RateCapDemotesSustainedNonRTPBulk(t *testing.T) {
	det := newRealtimeDetector()
	controller := newRealtimeControllerWithConfig(det, time.Second, time.Second)
	class := det.ClassifyOpen(NewFlowMeta("udp", "bulk.example:50000"))
	flowID := controller.Open(class)
	base := time.Unix(340, 0)
	bulk := make([]byte, 64*1024)
	seenBulk := false

	for i := 0; i < 20; i++ { // >1 MiB/s for ~1 second, with no RTP-version byte.
		at := base.Add(time.Duration(i) * 50 * time.Millisecond)
		if got := det.Observe(ObservedPacket{FlowID: flowID, At: at, Payload: bulk, Size: len(bulk), Direction: DirOutbound}); got == TrafficBulk {
			seenBulk = true
		}
	}
	if !seenBulk {
		t.Fatal("non-RTP sustained bulk never demoted to bulk")
	}
	stats := det.PlanBStats()
	if stats.Demotes < 1 {
		t.Fatalf("PlanB demotes = %d, want >= 1", stats.Demotes)
	}
	if stats.Lockins != 0 {
		t.Fatalf("PlanB lockins = %d, want 0", stats.Lockins)
	}
}

func testSTUNPayload() []byte {
	p := make([]byte, 20)
	binary.BigEndian.PutUint32(p[4:8], 0x2112a442)
	return p
}

func testDTLSHandshakePayload() []byte {
	p := make([]byte, 13)
	p[0], p[1], p[2] = 0x16, 0xfe, 0xfd
	return p
}

func testTURNChannelDataPayload() []byte {
	p := make([]byte, 8)
	binary.BigEndian.PutUint16(p[0:2], 0x4001)
	binary.BigEndian.PutUint16(p[2:4], 4)
	return p
}

func testRTPPayload(seq uint16, ssrc uint32) []byte {
	p := make([]byte, 80)
	p[0], p[1] = 0x80, 0x60
	binary.BigEndian.PutUint16(p[2:4], seq)
	binary.BigEndian.PutUint32(p[8:12], ssrc)
	return p
}

func detectorFlowStateForTest(t *testing.T, det *RealtimeDetector, flowID uint64) flowState {
	t.Helper()
	det.mu.Lock()
	defer det.mu.Unlock()
	st := det.flows[flowID]
	if st == nil {
		t.Fatalf("missing flow state for flow %d", flowID)
	}
	return *st
}

func TestStateBudget_FlowSizeUnder256B(t *testing.T) {
	if got := unsafe.Sizeof(flowState{}); got > 256 {
		t.Fatalf("flowState size = %d, want <= 256", got)
	}
}

func realtimeV2Observe(t *testing.T, det *RealtimeDetector, flowID uint64, at time.Time, payload []byte, size int, dir Direction) flowState {
	t.Helper()
	det.Observe(ObservedPacket{FlowID: flowID, At: at, Payload: payload, Size: size, Direction: dir})
	return detectorFlowStateForTest(t, det, flowID)
}

func TestRealtimeV2_PositiveSignatures(t *testing.T) {
	base := time.Unix(360, 0)
	raknet := make([]byte, 17)
	copy(raknet[1:9], []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe})
	cases := []struct {
		name string
		p    []byte
		flag uint8
	}{
		{"rtp", testRTPPayload(1, 0x01020304), POS_RTP},
		{"rtcp", []byte{0x80, 200, 0, 0, 0, 0, 0, 0}, POS_RTCP},
		{"stun", testSTUNPayload(), POS_STUN},
		{"turn", testTURNChannelDataPayload(), POS_TURN_DATA},
		{"raknet", raknet, POS_RAKNET},
		{"srceng", []byte{0xff, 0xff, 0xff, 0xff}, POS_SRCENG},
		{"dtls", testDTLSHandshakePayload(), POS_DTLS},
	}
	for i, tc := range cases {
		st := realtimeV2Observe(t, newRealtimeDetector(), uint64(10_000+i), base, tc.p, len(tc.p), DirOutbound)
		if st.flags&flagLiteLocked == 0 || st.posFlags&tc.flag == 0 || st.flags&flagBulkLocked != 0 {
			t.Fatalf("%s: flags=%08b pos=%02x", tc.name, st.flags, st.posFlags)
		}
	}
}

func TestRealtimeV2_NegativeSignatures(t *testing.T) {
	base := time.Unix(361, 0)
	ntp := make([]byte, 48)
	ntp[0] = 0x1b
	dns := make([]byte, 32)
	binary.BigEndian.PutUint16(dns[2:4], 0x0100)
	binary.BigEndian.PutUint16(dns[4:6], 1)
	cases := []struct {
		name string
		p    []byte
		flag uint8
	}{
		{"quic-long", []byte{0xc0, 0, 0, 0, 1, 0, 0}, NEG_QUIC_LONG},
		{"ntp", ntp, NEG_NTP},
		{"dns", dns, NEG_DNS},
	}
	for i, tc := range cases {
		st := realtimeV2Observe(t, newRealtimeDetector(), uint64(10_100+i), base, tc.p, len(tc.p), DirOutbound)
		if st.flags&flagBulkLocked == 0 || st.flags&flagLiteLocked != 0 || st.negFlags&tc.flag == 0 {
			t.Fatalf("%s: flags=%08b neg=%02x", tc.name, st.flags, st.negFlags)
		}
	}
}

func TestRealtimeV2_QuicCidStability(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(362, 0)
	for i := 0; i < 5; i++ {
		p := make([]byte, 1300)
		p[0] = 0x40
		copy(p[1:9], []byte{0xaa, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
		realtimeV2Observe(t, det, 10_200, base.Add(time.Duration(i)*20*time.Millisecond), p, len(p), DirInbound)
	}
	st := detectorFlowStateForTest(t, det, 10_200)
	if st.cidMatch < CID_MATCH_LOCK || st.negFlags&NEG_QUIC_CID == 0 || st.flags&flagLiteLocked != 0 {
		t.Fatalf("cid=%d flags=%08b neg=%02x", st.cidMatch, st.flags, st.negFlags)
	}
}

func TestRealtimeV2_TurnVsQuic(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(363, 0)
	for i := 0; i < 5; i++ {
		p := make([]byte, 1300)
		binary.BigEndian.PutUint16(p[0:2], 0x4001)
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)-4))
		copy(p[4:9], []byte{0x44, 0x55, 0x66, 0x77, 0x88})
		realtimeV2Observe(t, det, 10_300, base.Add(time.Duration(i)*20*time.Millisecond), p, len(p), DirInbound)
	}
	st := detectorFlowStateForTest(t, det, 10_300)
	if st.posFlags&POS_TURN_DATA != 0 || st.negFlags&NEG_QUIC_CID == 0 || st.flags&flagLiteLocked != 0 {
		t.Fatalf("flags=%08b pos=%02x neg=%02x", st.flags, st.posFlags, st.negFlags)
	}
}

func TestRealtimeV2_RateLockNoSignature(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(364, 0)
	payload := make([]byte, 300)
	payload[0] = 0x31
	for i := 0; i < 24; i++ {
		dir := DirOutbound
		if i%2 == 1 {
			dir = DirInbound
		}
		realtimeV2Observe(t, det, 10_400, base.Add(time.Duration(i)*33*time.Millisecond), payload, len(payload), dir)
	}
	st := detectorFlowStateForTest(t, det, 10_400)
	if st.flags&flagLiteLocked == 0 || st.posFlags != 0 || st.negFlags != 0 {
		t.Fatalf("flags=%08b score=%d smooth=%d failed=%d pos=%02x neg=%02x", st.flags, st.score, st.clsSmoothWins, st.clsFailedWins, st.posFlags, st.negFlags)
	}
}

func TestRealtimeV2_QuicAckBurstNoLock(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(365, 0)
	for i := 0; i < 12; i++ {
		sz := 50
		if i%3 == 1 {
			sz = 1300
		}
		p := make([]byte, sz)
		p[0] = 0x31
		realtimeV2Observe(t, det, 10_500, base.Add(time.Duration(i*i+1)*7*time.Millisecond), p, sz, DirInbound)
	}
	st := detectorFlowStateForTest(t, det, 10_500)
	if st.flags&flagLiteLocked != 0 || st.flags&flagBulkLocked == 0 {
		t.Fatalf("flags=%08b score=%d neg=%02x", st.flags, st.score, st.negFlags)
	}
}

func TestRealtimeV2_VoiceWithSilenceHysteresis(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(366, 0)
	for i := 0; i < 50; i++ {
		realtimeV2Observe(t, det, 10_600, base.Add(time.Duration(i)*20*time.Millisecond), testRTPPayload(uint16(i), 0x0a0b0c0d), 80, DirOutbound)
	}
	st := realtimeV2Observe(t, det, 10_600, base.Add(4*time.Second), testRTPPayload(51, 0x0a0b0c0d), 80, DirOutbound)
	if st.flags&flagLiteLocked == 0 || st.flags&flagBulkLocked != 0 {
		t.Fatalf("flags=%08b score=%d", st.flags, st.score)
	}
}

func TestRealtimeV2_CoolingReturnToLite(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(367, 0)
	flowID := uint64(10_650)
	ssrc := uint32(0x0a0b0c0d)

	for i := 0; i < 50; i++ {
		realtimeV2Observe(t, det, flowID, base.Add(time.Duration(i)*20*time.Millisecond), testRTPPayload(uint16(i), ssrc), 80, DirOutbound)
	}
	if st := detectorFlowStateForTest(t, det, flowID); st.flags&flagLiteLocked == 0 || st.flags&flagInCooling != 0 {
		t.Fatalf("pre-cooling flags=%08b score=%d", st.flags, st.score)
	}

	var st flowState
	for i := 0; i < 5; i++ {
		st = realtimeV2Observe(t, det, flowID, base.Add(6*time.Second+time.Duration(i)*20*time.Millisecond), testRTPPayload(uint16(50+i), ssrc), 80, DirOutbound)
	}
	if st.flags&flagLiteLocked == 0 || st.flags&flagInCooling != 0 {
		t.Fatalf("post-cooling flags=%08b score=%d", st.flags, st.score)
	}
}

func TestRealtimeV2_BulkSticky(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(367, 0)
	realtimeV2Observe(t, det, 10_700, base, []byte{0xc0, 0, 0, 0, 1, 0, 0}, 7, DirOutbound)
	st := realtimeV2Observe(t, det, 10_700, base.Add(20*time.Millisecond), testRTPPayload(1, 0x01020304), 80, DirOutbound)
	if st.flags&flagBulkLocked == 0 || st.flags&flagLiteLocked != 0 || st.posFlags != 0 {
		t.Fatalf("flags=%08b pos=%02x", st.flags, st.posFlags)
	}
}

func TestTier1_STUNCookieAlone(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(200, 0)
	class := det.Observe(ObservedPacket{FlowID: 1, At: base, Payload: testSTUNPayload(), Size: 20, Direction: DirOutbound})
	if class != TrafficBulk {
		t.Fatalf("single STUN packet class = %s, want bulk until confirm", class)
	}
	st := detectorFlowStateForTest(t, det, 1)
	if st.state != flowStateProvisionalRT {
		t.Fatalf("single STUN state = %d, want PROVISIONAL_RT", st.state)
	}
	if got := st.scoreT1; got != det.cfg.StunScoreQ8 {
		t.Fatalf("STUN scoreT1 = %d, want %d", got, det.cfg.StunScoreQ8)
	}
}

func TestTier1_STUNPlusAppHintClassifiesRealtime(t *testing.T) {
	det := newRealtimeDetector()
	if got := det.ClassifyOpen(FlowMeta{Network: "udp", Address: "1.2.3.4:9999", Payload: testSTUNPayload(), AppHint: "anydesk-service"}); got != TrafficRealtime {
		t.Fatalf("STUN+apphint class = %s, want realtime", got)
	}
}

func TestTier1_RTPSinglePacketDoesNotPromote(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(210, 0)
	class := det.Observe(ObservedPacket{FlowID: 2, At: base, Payload: testRTPPayload(10, 0x01020304), Size: 80, Direction: DirOutbound})
	if class != TrafficBulk {
		t.Fatalf("single RTP packet class = %s, want bulk", class)
	}
	st := detectorFlowStateForTest(t, det, 2)
	if st.state != flowStateProvisionalBulk {
		t.Fatalf("single RTP state = %d, want PROVISIONAL_BULK", st.state)
	}
}

func TestTier1_RTPThreePacketConfirmsCandidateOnlyToProvisionalRT(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(220, 0)
	for i := 0; i < 3; i++ {
		det.Observe(ObservedPacket{FlowID: 3, At: base.Add(time.Duration(i) * 20 * time.Millisecond), Payload: testRTPPayload(uint16(100+i), 0x0a0b0c0d), Size: 80, Direction: DirOutbound})
	}
	st := detectorFlowStateForTest(t, det, 3)
	if st.state != flowStateProvisionalRT {
		t.Fatalf("3-packet RTP state = %d, want PROVISIONAL_RT", st.state)
	}
	if got := st.scoreT1; got != det.cfg.RtpConfirmedScoreQ8 {
		t.Fatalf("RTP confirmed scoreT1 = %d, want %d", got, det.cfg.RtpConfirmedScoreQ8)
	}
}

func TestTier1_DTLSAndTURNStrongPrefixes(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(230, 0)
	det.Observe(ObservedPacket{FlowID: 4, At: base, Payload: testDTLSHandshakePayload(), Size: 13, Direction: DirOutbound})
	if st := detectorFlowStateForTest(t, det, 4); st.state != flowStateProvisionalRT || st.scoreT1 != det.cfg.DtlsHandshakeScoreQ8 {
		t.Fatalf("DTLS state/score = %d/%d, want PROVISIONAL_RT/%d", st.state, st.scoreT1, det.cfg.DtlsHandshakeScoreQ8)
	}
	det.Observe(ObservedPacket{FlowID: 5, At: base, Payload: testTURNChannelDataPayload(), Size: 8, Direction: DirOutbound})
	if st := detectorFlowStateForTest(t, det, 5); st.state != flowStateProvisionalRT || st.scoreT1 != det.cfg.TurnChannelDataScoreQ8 {
		t.Fatalf("TURN state/score = %d/%d, want PROVISIONAL_RT/%d", st.state, st.scoreT1, det.cfg.TurnChannelDataScoreQ8)
	}
}

func TestTier1_QuicAndTLSLargePenalties(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(240, 0)
	quic := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0}
	det.Observe(ObservedPacket{FlowID: 6, At: base, Payload: quic, Size: len(quic), Direction: DirOutbound})
	if st := detectorFlowStateForTest(t, det, 6); st.scoreT1 != det.cfg.QuicLongHeaderScoreQ8 {
		t.Fatalf("QUIC scoreT1 = %d, want %d", st.scoreT1, det.cfg.QuicLongHeaderScoreQ8)
	}
	tls := make([]byte, 1413)
	tls[0], tls[1], tls[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(tls[3:5], 1408)
	det.Observe(ObservedPacket{FlowID: 7, At: base, Payload: tls, Size: len(tls), Direction: DirInbound})
	if st := detectorFlowStateForTest(t, det, 7); st.scoreT1 != det.cfg.TlsLargeAppDataScoreQ8 {
		t.Fatalf("TLS-large scoreT1 = %d, want %d", st.scoreT1, det.cfg.TlsLargeAppDataScoreQ8)
	}
}

func TestTier2_OpusVoiceCadence(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(250, 0)
	class := TrafficBulk
	for i := 0; i < 30; i++ {
		dir := DirOutbound
		if i%2 == 1 {
			dir = DirInbound
		}
		payload := make([]byte, 80)
		class = det.Observe(ObservedPacket{FlowID: 8, At: base.Add(time.Duration(i) * 20 * time.Millisecond), Payload: payload, Size: len(payload), Direction: dir})
	}
	if class != TrafficRealtime {
		t.Fatalf("voice cadence class = %s, want realtime", class)
	}
	if st := detectorFlowStateForTest(t, det, 8); st.state != flowStateConfirmedRT {
		t.Fatalf("voice cadence state = %d, want CONFIRMED_RT", st.state)
	}
}

func TestTier2_BulkMTUConfirmsBulk(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(260, 0)
	for i := 0; i < 60; i++ {
		payload := make([]byte, 1460)
		det.Observe(ObservedPacket{FlowID: 9, At: base.Add(time.Duration(i) * 120 * time.Millisecond), Payload: payload, Size: len(payload), Direction: DirInbound})
	}
	st := detectorFlowStateForTest(t, det, 9)
	if st.state != flowStateConfirmedBulk {
		t.Fatalf("MTU bulk state = %d, want CONFIRMED_BULK", st.state)
	}
	if st.scoreT2 > det.cfg.MtuBulkScoreQ8 {
		t.Fatalf("MTU bulk scoreT2 = %d, want penalty at least %d", st.scoreT2, det.cfg.MtuBulkScoreQ8)
	}
}

func TestTier2_PaddedRealtimeDoesNotGetMTUPenalty(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(270, 0)
	class := TrafficBulk
	for i := 0; i < 30; i++ {
		dir := DirOutbound
		if i%2 == 1 {
			dir = DirInbound
		}
		payload := make([]byte, 1500)
		class = det.Observe(ObservedPacket{FlowID: 10, At: base.Add(time.Duration(i) * 20 * time.Millisecond), Payload: payload, Size: len(payload), Direction: dir})
	}
	if class != TrafficRealtime {
		t.Fatalf("padded realtime class = %s, want realtime", class)
	}
	st := detectorFlowStateForTest(t, det, 10)
	if st.scoreT2 <= 0 {
		t.Fatalf("padded realtime scoreT2 = %d, want positive cadence without MTU penalty", st.scoreT2)
	}
}

func TestTier2_TCPSkipsCadence(t *testing.T) {
	det := newRealtimeDetector()
	class := det.ClassifyOpen(NewFlowMeta("tcp", "example.com:12345"))
	controller := newRealtimeControllerWithConfig(det, time.Second, time.Second)
	flowID := controller.Open(class)
	base := time.Unix(280, 0)
	for i := 0; i < 10; i++ {
		det.Observe(ObservedPacket{FlowID: flowID, At: base.Add(time.Duration(i) * 20 * time.Millisecond), Payload: make([]byte, 80), Size: 80, Direction: DirUnknown})
	}
	st := detectorFlowStateForTest(t, det, flowID)
	if st.scoreT2 != 0 || st.state == flowStateConfirmedRT {
		t.Fatalf("TCP cadence score/state = %d/%d, want no Tier2 promotion", st.scoreT2, st.state)
	}
}

func TestStateMachine_AntiFlap_BulkPinned(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(290, 0)
	for i := 0; i < 6; i++ {
		det.Observe(ObservedPacket{FlowID: 11, At: base.Add(time.Duration(i) * 200 * time.Millisecond), Payload: make([]byte, 1460), Size: 1460, Direction: DirInbound})
	}
	if st := detectorFlowStateForTest(t, det, 11); st.state != flowStateConfirmedBulk {
		t.Fatalf("pre-STUN state = %d, want CONFIRMED_BULK", st.state)
	}
	det.Observe(ObservedPacket{FlowID: 11, At: base.Add(2 * time.Second), Payload: testSTUNPayload(), Size: 20, Direction: DirOutbound})
	if st := detectorFlowStateForTest(t, det, 11); st.state != flowStateConfirmedBulk {
		t.Fatalf("post-STUN state = %d, want pinned CONFIRMED_BULK", st.state)
	}
}

func TestStateMachine_SilentDemote(t *testing.T) {
	det := newRealtimeDetector()
	base := time.Unix(300, 0)
	det.Observe(ObservedPacket{FlowID: 12, At: base, Payload: testSTUNPayload(), Size: 20, Direction: DirOutbound})
	// Accumulate cadence breaks so score drops below demote after the silent-demote age.
	for i := 1; i <= 15; i++ {
		det.Observe(ObservedPacket{FlowID: 12, At: base.Add(time.Duration(i) * 200 * time.Millisecond), Payload: []byte{1}, Size: 1, Direction: DirOutbound})
	}
	st := detectorFlowStateForTest(t, det, 12)
	if st.state != flowStateProvisionalBulk {
		t.Fatalf("silent-demoted state = %d, want PROVISIONAL_BULK", st.state)
	}
}

func TestStateMachine_IdleRelease(t *testing.T) {
	det := newRealtimeDetector()
	controller := newRealtimeControllerWithConfig(det, 10*time.Millisecond, 10*time.Millisecond)
	flowID := controller.Open(TrafficBulk)
	base := time.Unix(310, 0)
	for i := 0; i < 30; i++ {
		dir := DirOutbound
		if i%2 == 1 {
			dir = DirInbound
		}
		controller.observePacketAt(flowID, make([]byte, 80), dir, base.Add(time.Duration(i)*20*time.Millisecond))
	}
	if controller.ActiveRealtimeCount() != 1 {
		t.Fatalf("active realtime after promote = %d, want 1", controller.ActiveRealtimeCount())
	}
	det.sweepIdleForTest(base.Add(31 * time.Second))
	if controller.ActiveRealtimeCount() != 0 {
		t.Fatalf("active realtime after idle release = %d, want 0", controller.ActiveRealtimeCount())
	}
}

func TestEndpointCache_SiblingFlowBoostAndTTL(t *testing.T) {
	det := newRealtimeDetector()
	// Opt out: this legacy cache test asserts pre-Plan-B UDP/9999 opens stay bulk.
	det.cfg.PlanBDefaultPromoteUDP = false
	base := time.Unix(320, 0)
	class := det.ClassifyOpen(FlowMeta{Network: "udp", Address: "1.2.3.4:9999", Payload: testSTUNPayload(), AppHint: "anydesk"})
	controller := newRealtimeControllerWithConfig(det, time.Second, time.Second)
	flowID := controller.Open(class)
	// Bind and confirm the first endpoint in the cache.
	det.Observe(ObservedPacket{FlowID: flowID, At: base.Add(250 * time.Millisecond), Payload: make([]byte, 80), Size: 80, Direction: DirOutbound})
	if got := det.ClassifyOpen(FlowMeta{Network: "udp", Address: "1.2.3.5:9999"}); got != TrafficBulk {
		// Cache hit alone is a watch/provisional signal, not enough to confirm via ClassifyOpen.
		t.Fatalf("sibling cache class = %s, want bulk until corroborated", got)
	}
	pending := det.pendingOpenStateForTest()
	if pending.scoreT3 <= det.cfg.UdpPriorScoreQ4 {
		t.Fatalf("sibling cache scoreT3 = %d, want endpoint cache boost above UDP prior", pending.scoreT3)
	}
	det.expireEndpointCacheForTest(base.Add(61 * time.Second))
	det.ClassifyOpen(FlowMeta{Network: "udp", Address: "1.2.3.6:9999"})
	pending = det.pendingOpenStateForTest()
	if pending.scoreT3 != det.cfg.UdpPriorScoreQ4 {
		t.Fatalf("expired cache scoreT3 = %d, want only UDP prior %d", pending.scoreT3, det.cfg.UdpPriorScoreQ4)
	}
}

func TestRealtimeDetectorDropsIANADynamicRangeDefault(t *testing.T) {
	det := newRealtimeDetector()
	// Opt out: Plan B intentionally default-promotes non-DNS UDP dynamic ports.
	det.cfg.PlanBDefaultPromoteUDP = false
	if got := det.ClassifyOpen(NewFlowMeta("udp", "example.com:50000")); got != TrafficBulk {
		t.Fatalf("IANA dynamic UDP port class = %s, want bulk", got)
	}
}

type planBPlusBlockingRWC struct {
	closed chan struct{}
	once   sync.Once
}

func newPlanBPlusBlockingRWC() *planBPlusBlockingRWC {
	return &planBPlusBlockingRWC{closed: make(chan struct{})}
}

func (r *planBPlusBlockingRWC) Read(p []byte) (int, error) {
	<-r.closed
	return 0, io.EOF
}

func (r *planBPlusBlockingRWC) Write(p []byte) (int, error) { return len(p), nil }

func (r *planBPlusBlockingRWC) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func waitForPlanBPlusMigrationFires(t *testing.T, det *RealtimeDetector, want uint64) {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	for {
		if got := det.PlanBStats().MigrationFires; got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("MigrationFires = %d, want %d", det.PlanBStats().MigrationFires, want)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func newPlanBPlusDetectorForTest(cfg RealtimeDetectorConfig) (*RealtimeDetector, *RealtimeController) {
	cfg.RealtimePorts = []int{3478}
	cfg.PlanBDefaultPromoteUDP = true
	cfg.PlanBRateCapWindow = 500 * time.Millisecond
	cfg.PlanBRateCapBytesPerSec = 256 * 1024
	if cfg.MigrationDebounceWindow == 0 {
		cfg.MigrationDebounceWindow = 1500 * time.Millisecond
	}
	if cfg.MigrationWindowByteThreshold == 0 {
		cfg.MigrationWindowByteThreshold = 384 * 1024
	}
	if cfg.MigrationCumulativeFloor == 0 {
		cfg.MigrationCumulativeFloor = 10 * 1024 * 1024
	}
	det := newRealtimeDetectorWithConfig(cfg)
	controller := newRealtimeControllerWithConfig(det, time.Second, time.Second)
	return det, controller
}

func registerPlanBPlusMigrationHandle(t *testing.T, det *RealtimeDetector, flowID uint64, dst string, rwc *planBPlusBlockingRWC, originalLite bool) {
	t.Helper()
	det.registerMigrationHandle(flowID, &migrationHandle{
		fastCloseFn:           rwc.Close,
		dstAddr:               dst,
		originalTransportLite: originalLite,
		ensureBulkFn:          func() error { return nil },
	})
}

func TestPlanBPlus_MigrationWindowByteThresholdFiresOnSustainedBulk(t *testing.T) {
	det, controller := newPlanBPlusDetectorForTest(RealtimeDetectorConfig{MigrationEnabled: true})
	dst := "bulk.example:443"
	class := det.ClassifyOpen(NewFlowMeta("udp", dst))
	flowID := controller.Open(class)
	rwc := newPlanBPlusBlockingRWC()
	registerPlanBPlusMigrationHandle(t, det, flowID, dst, rwc, true)
	pc := wrapRealtimePacketConn(newUDPFramedPacketConn(rwc, &streamAddr{network: "udp", address: dst}), controller, flowID)

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, _, err := pc.ReadFrom(buf)
		readErr <- err
	}()

	base := time.Unix(400, 0)
	payload := make([]byte, 256*1024)
	for i := 0; i < 48; i++ { // 12 MiB over ~2.9 s, enough to cross floor and per-window threshold.
		at := base.Add(time.Duration(i) * 60 * time.Millisecond)
		det.Observe(ObservedPacket{FlowID: flowID, At: at, Payload: payload, Size: len(payload), Direction: DirOutbound})
	}
	waitForPlanBPlusMigrationFires(t, det, 1)

	select {
	case err := <-readErr:
		if err != io.EOF {
			t.Fatalf("ReadFrom after migration err = %v, want io.EOF", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("original PacketConn ReadFrom did not unblock after migration")
	}

	st := detectorFlowStateForTest(t, det, flowID)
	if st.windowByteSum < det.cfg.MigrationWindowByteThreshold {
		t.Fatalf("windowByteSum = %d, want >= %d", st.windowByteSum, det.cfg.MigrationWindowByteThreshold)
	}
	if st.totalBytes < det.cfg.MigrationCumulativeFloor {
		t.Fatalf("totalBytes = %d, want >= %d", st.totalBytes, det.cfg.MigrationCumulativeFloor)
	}
	if !st.migrated {
		t.Fatal("flow state did not record migrated=true")
	}
	key := forceBulkCacheKey(NewFlowMeta("udp", dst))
	v, ok := det.forceBulkCache.Load(key)
	if !ok {
		t.Fatalf("forceBulkCache missing key %q", key)
	}
	if until := v.(forceBulkEntry).untilNS; until <= time.Now().UnixNano() {
		t.Fatalf("forceBulkCache untilNS = %d, want future", until)
	}
	if got := det.ClassifyOpen(NewFlowMeta("udp", dst)); got != TrafficBulk {
		t.Fatalf("fresh same-dst ClassifyOpen = %s, want bulk from forceBulkCache", got)
	}
}

func TestPlanBPlus_MigrationSkippedOnSingleBurst(t *testing.T) {
	det, controller := newPlanBPlusDetectorForTest(RealtimeDetectorConfig{MigrationEnabled: true})
	dst := "burst.example:443"
	flowID := controller.Open(det.ClassifyOpen(NewFlowMeta("udp", dst)))
	rwc := newPlanBPlusBlockingRWC()
	defer rwc.Close()
	registerPlanBPlusMigrationHandle(t, det, flowID, dst, rwc, true)
	base := time.Unix(410, 0)
	det.Observe(ObservedPacket{FlowID: flowID, At: base, Payload: make([]byte, 200*1024), Size: 200 * 1024, Direction: DirOutbound})
	det.Observe(ObservedPacket{FlowID: flowID, At: base.Add(2 * time.Second), Payload: []byte{1}, Size: 1, Direction: DirOutbound})
	st := detectorFlowStateForTest(t, det, flowID)
	if st.windowByteSum >= det.cfg.MigrationWindowByteThreshold {
		t.Fatalf("windowByteSum = %d, want below threshold %d", st.windowByteSum, det.cfg.MigrationWindowByteThreshold)
	}
	if got := det.PlanBStats().MigrationFires; got != 0 {
		t.Fatalf("MigrationFires = %d, want 0", got)
	}
}

func TestPlanBPlus_MigrationSkippedBelowFloor(t *testing.T) {
	det, controller := newPlanBPlusDetectorForTest(RealtimeDetectorConfig{MigrationEnabled: true})
	dst := "below-floor.example:443"
	flowID := controller.Open(det.ClassifyOpen(NewFlowMeta("udp", dst)))
	rwc := newPlanBPlusBlockingRWC()
	defer rwc.Close()
	registerPlanBPlusMigrationHandle(t, det, flowID, dst, rwc, true)
	base := time.Unix(420, 0)
	payload := make([]byte, 256*1024)
	for i := 0; i < 4; i++ { // 1 MiB in one tumbling window: candidate fires, 10 MiB floor blocks.
		det.Observe(ObservedPacket{FlowID: flowID, At: base.Add(time.Duration(i) * 200 * time.Millisecond), Payload: payload, Size: len(payload), Direction: DirOutbound})
	}
	stats := det.PlanBStats()
	if stats.MigrationFires != 0 {
		t.Fatalf("MigrationFires = %d, want 0", stats.MigrationFires)
	}
	if stats.MigrationSkippedFloor < 1 {
		t.Fatalf("MigrationSkippedFloor = %d, want >= 1", stats.MigrationSkippedFloor)
	}
}

func TestPlanBPlus_MigrationSkippedRTPLocked(t *testing.T) {
	det, controller := newPlanBPlusDetectorForTest(RealtimeDetectorConfig{MigrationEnabled: true})
	dst := "rtp.example:50000"
	flowID := controller.Open(det.ClassifyOpen(NewFlowMeta("udp", dst)))
	rwc := newPlanBPlusBlockingRWC()
	defer rwc.Close()
	registerPlanBPlusMigrationHandle(t, det, flowID, dst, rwc, true)
	base := time.Unix(430, 0)
	det.Observe(ObservedPacket{FlowID: flowID, At: base, Payload: testRTPPayload(1, 0x01020304), Size: 80, Direction: DirInbound})
	payload := make([]byte, 256*1024)
	for i := 0; i < 48; i++ {
		det.Observe(ObservedPacket{FlowID: flowID, At: base.Add(time.Duration(i+1) * 60 * time.Millisecond), Payload: payload, Size: len(payload), Direction: DirOutbound})
	}
	stats := det.PlanBStats()
	if stats.Lockins < 1 {
		t.Fatalf("Lockins = %d, want >= 1", stats.Lockins)
	}
	if stats.MigrationFires != 0 {
		t.Fatalf("MigrationFires = %d, want 0", stats.MigrationFires)
	}
}

func TestPlanBPlus_MigrationDisabled(t *testing.T) {
	det, controller := newPlanBPlusDetectorForTest(RealtimeDetectorConfig{MigrationEnabled: false})
	dst := "disabled.example:443"
	flowID := controller.Open(det.ClassifyOpen(NewFlowMeta("udp", dst)))
	rwc := newPlanBPlusBlockingRWC()
	defer rwc.Close()
	registerPlanBPlusMigrationHandle(t, det, flowID, dst, rwc, true)
	base := time.Unix(440, 0)
	payload := make([]byte, 256*1024)
	for i := 0; i < 48; i++ {
		det.Observe(ObservedPacket{FlowID: flowID, At: base.Add(time.Duration(i) * 60 * time.Millisecond), Payload: payload, Size: len(payload), Direction: DirOutbound})
	}
	if got := det.PlanBStats().MigrationFires; got != 0 {
		t.Fatalf("MigrationFires = %d, want 0", got)
	}
	if _, ok := det.forceBulkCache.Load(forceBulkCacheKey(NewFlowMeta("udp", dst))); ok {
		t.Fatal("forceBulkCache populated even though migration disabled")
	}
}

func TestPlanBPlus_HysteresisDefaults15s(t *testing.T) {
	controller := newRealtimeController()
	if controller.hysteresisMin != 15*time.Second {
		t.Fatalf("hysteresisMin = %s, want 15s", controller.hysteresisMin)
	}
	if controller.hysteresisMax != 30*time.Second {
		t.Fatalf("hysteresisMax = %s, want 30s", controller.hysteresisMax)
	}
}

func TestPlanBPlus_ServerObservationOpenAndClose(t *testing.T) {
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{PlanBDefaultPromoteUDP: true, MigrationEnabled: false})
	s := &Server{realtime: newRealtimeControllerWithConfig(det, time.Second, time.Second)}
	class := s.realtime.Detector.ClassifyOpen(NewFlowMeta("udp", "voice.example:50000"))
	flowID := s.realtime.Open(class)
	if got := s.realtime.ActiveRealtimeCount(); got != 1 {
		t.Fatalf("server active realtime after UDP open = %d, want 1", got)
	}
	s.realtime.Close(flowID)
	if got := s.realtime.ActiveRealtimeCount(); got != 0 {
		t.Fatalf("server active realtime after UDP close = %d, want 0", got)
	}
}

func TestPlanBPlus_ServerObservationDemoteOnRateCap(t *testing.T) {
	det := newRealtimeDetectorWithConfig(RealtimeDetectorConfig{
		PlanBDefaultPromoteUDP:  true,
		PlanBRateCapWindow:      500 * time.Millisecond,
		PlanBRateCapBytesPerSec: 256 * 1024,
		MigrationEnabled:        false,
	})
	s := &Server{realtime: newRealtimeControllerWithConfig(det, time.Second, time.Second)}
	flowID := s.realtime.Open(s.realtime.Detector.ClassifyOpen(NewFlowMeta("udp", "bulk.example:50000")))
	if got := s.realtime.ActiveRealtimeCount(); got != 1 {
		t.Fatalf("server active realtime after open = %d, want 1", got)
	}
	base := time.Unix(450, 0)
	payload := make([]byte, 64*1024)
	for i := 0; i < 20; i++ {
		s.realtime.observePacketAt(flowID, payload, DirOutbound, base.Add(time.Duration(i)*50*time.Millisecond))
	}
	if got := s.realtime.ActiveRealtimeCount(); got != 0 {
		t.Fatalf("server active realtime after rate-cap demote = %d, want 0", got)
	}
	if got := det.PlanBStats().Demotes; got < 1 {
		t.Fatalf("PlanB Demotes = %d, want >= 1", got)
	}
}
