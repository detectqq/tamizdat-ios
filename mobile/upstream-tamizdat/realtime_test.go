package tamizdat

import (
	"net"
	"testing"
	"time"
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
