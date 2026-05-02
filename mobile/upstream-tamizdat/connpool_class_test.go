package tamizdat

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newClassTestPool(t *testing.T, maxStreams, minTransports, maxTransports int, overlapAllowance ...int) (*connPool, *atomic.Int32) {
	t.Helper()
	allowance := -1
	if len(overlapAllowance) > 0 {
		allowance = overlapAllowance[0]
	}
	var created atomic.Int32
	p := newConnPool(maxStreams, time.Hour, minTransports, maxTransports, 13312, allowance, func(ctx context.Context, class TrafficClass) (*h2Transport, error) {
		created.Add(1)
		tr := &h2Transport{maxStreams: maxStreams, drainTimeout: 10 * time.Millisecond}
		prepareTransportForClass(tr, class)
		tr.touch()
		return tr, nil
	})
	p.liteCloseMin = 20 * time.Millisecond
	p.liteCloseMax = 20 * time.Millisecond
	t.Cleanup(func() { _ = p.close() })
	return p, &created
}

func wireRealtimeTestCallbacks(p *connPool, c *RealtimeController) {
	p.setRealtimeController(c)
	c.onLastRealtimeClose = p.armLiteCloseHysteresis
	c.onRealtimeOpen = p.cancelLiteCloseHysteresis
}

func poolClassCounts(p *connPool) (total, bulk, lite int, liteTransport *h2Transport) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tr := range p.transports {
		total++
		switch tr.class {
		case TrafficRealtime:
			lite++
			if liteTransport == nil {
				liteTransport = tr
			}
		default:
			bulk++
		}
	}
	return total, bulk, lite, liteTransport
}

func findClassTransport(p *connPool, class TrafficClass) *h2Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tr := range p.transports {
		if tr.class == class {
			return tr
		}
	}
	return nil
}

func eventuallyV2(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not satisfied within %s", timeout)
	}
}

func TestPool_GetForRealtimeOpensSecondTransport(t *testing.T) {
	p, _ := newClassTestPool(t, 10, 1, 2)
	p.topUp()
	if total, bulk, lite, _ := poolClassCounts(p); total != 1 || bulk != 1 || lite != 0 {
		t.Fatalf("after topUp counts total/bulk/lite = %d/%d/%d, want 1/1/0", total, bulk, lite)
	}

	tr, err := p.getTransportForClass(context.Background(), TrafficRealtime)
	if err != nil {
		t.Fatalf("get realtime transport: %v", err)
	}
	defer tr.releaseStreamSlot()

	if tr.class != TrafficRealtime {
		t.Fatalf("realtime transport class = %s, want realtime", tr.class)
	}
	if got := ShapeMode(tr.shapeMode.Load()); got != ShapeLite {
		t.Fatalf("realtime transport shape = %s, want lite", got)
	}
	if total, bulk, lite, liteTr := poolClassCounts(p); total != 2 || bulk != 1 || lite != 1 || liteTr != tr {
		t.Fatalf("counts total/bulk/lite/litePtr = %d/%d/%d/%p, want 2/1/1/%p", total, bulk, lite, liteTr, tr)
	}
}

func TestPool_BulkClassNeverPicksLite(t *testing.T) {
	p, _ := newClassTestPool(t, 200, 1, 2)
	p.topUp()
	lite, err := p.getTransportForClass(context.Background(), TrafficRealtime)
	if err != nil {
		t.Fatalf("get realtime: %v", err)
	}
	defer lite.releaseStreamSlot()
	initialLiteStreams := lite.streamCount()

	for i := 0; i < 100; i++ {
		tr, err := p.getTransportForClass(context.Background(), TrafficBulk)
		if err != nil {
			t.Fatalf("bulk get %d: %v", i, err)
		}
		if tr.class != TrafficBulk {
			t.Fatalf("bulk get %d returned class %s", i, tr.class)
		}
		tr.releaseStreamSlot()
	}
	if got := lite.streamCount(); got != initialLiteStreams {
		t.Fatalf("lite streamCount = %d, want unchanged %d", got, initialLiteStreams)
	}
}

func TestPool_RealtimeClassNeverPicksBulk(t *testing.T) {
	p, _ := newClassTestPool(t, 20, 1, 2)
	p.topUp()
	var lite *h2Transport
	for i := 0; i < 5; i++ {
		tr, err := p.getTransportForClass(context.Background(), TrafficRealtime)
		if err != nil {
			t.Fatalf("realtime get %d: %v", i, err)
		}
		if tr.class != TrafficRealtime {
			t.Fatalf("realtime get %d returned class %s", i, tr.class)
		}
		if lite == nil {
			lite = tr
		} else if tr != lite {
			t.Fatalf("realtime get %d returned different lite transport %p != %p", i, tr, lite)
		}
	}
	if got := lite.streamCount(); got != 5 {
		t.Fatalf("lite streamCount = %d, want 5", got)
	}
	for i := 0; i < 5; i++ {
		lite.releaseStreamSlot()
	}
}

func TestPool_LiteHysteresisDelayedClose(t *testing.T) {
	p, _ := newClassTestPool(t, 10, 1, 2)
	p.liteCloseMin = 40 * time.Millisecond
	p.liteCloseMax = 40 * time.Millisecond
	controller := newRealtimeControllerWithConfig(newRealtimeDetector(), time.Hour, time.Hour)
	wireRealtimeTestCallbacks(p, controller)
	p.topUp()

	flowID := controller.Open(TrafficRealtime)
	lite, err := p.getTransportForClass(context.Background(), TrafficRealtime)
	if err != nil {
		t.Fatalf("get realtime: %v", err)
	}
	lite.releaseStreamSlot()
	controller.Close(flowID)

	time.Sleep(15 * time.Millisecond)
	if lite.isDraining() || lite.isClosed() {
		t.Fatal("lite transport closed before hysteresis min elapsed")
	}
	if total, bulk, liteCount, _ := poolClassCounts(p); total != 2 || bulk != 1 || liteCount != 1 {
		t.Fatalf("during hysteresis counts = %d/%d/%d, want 2/1/1", total, bulk, liteCount)
	}

	eventuallyV2(t, 250*time.Millisecond, func() bool {
		total, bulk, liteCount, litePtr := poolClassCounts(p)
		return total == 1 && bulk == 1 && liteCount == 0 && litePtr == nil
	})
}

func TestPool_LiteHysteresisCancelOnReopen(t *testing.T) {
	p, created := newClassTestPool(t, 10, 1, 2)
	p.liteCloseMin = 100 * time.Millisecond
	p.liteCloseMax = 100 * time.Millisecond
	controller := newRealtimeControllerWithConfig(newRealtimeDetector(), time.Hour, time.Hour)
	wireRealtimeTestCallbacks(p, controller)
	p.topUp()

	flowID := controller.Open(TrafficRealtime)
	lite, err := p.getTransportForClass(context.Background(), TrafficRealtime)
	if err != nil {
		t.Fatalf("get realtime: %v", err)
	}
	lite.releaseStreamSlot()
	controller.Close(flowID)
	time.Sleep(10 * time.Millisecond)

	flowID2 := controller.Open(TrafficRealtime)
	lite2, err := p.getTransportForClass(context.Background(), TrafficRealtime)
	if err != nil {
		t.Fatalf("reopen realtime: %v", err)
	}
	if lite2 != lite {
		t.Fatalf("reopen got new lite %p, want existing %p", lite2, lite)
	}
	if p.liteCloseDeadline.Load() != 0 {
		t.Fatal("lite close deadline still armed after realtime reopen")
	}
	if got := created.Load(); got != 2 {
		t.Fatalf("created transports = %d, want 2 (bulk+lite, no redial)", got)
	}
	lite2.releaseStreamSlot()
	controller.Close(flowID2)
}

func TestPool_LiteCloseRaceWithReopen(t *testing.T) {
	for trial := 0; trial < 100; trial++ {
		p, _ := newClassTestPool(t, 10, 1, 2)
		p.liteCloseMin = time.Hour
		p.liteCloseMax = time.Hour
		controller := newRealtimeControllerWithConfig(newRealtimeDetector(), time.Hour, time.Hour)
		wireRealtimeTestCallbacks(p, controller)
		p.topUp()

		flowID := controller.Open(TrafficRealtime)
		lite, err := p.getTransportForClass(context.Background(), TrafficRealtime)
		if err != nil {
			t.Fatalf("trial %d get realtime: %v", trial, err)
		}
		lite.releaseStreamSlot()
		controller.Close(flowID)

		p.mu.Lock()
		if p.liteCloseTimer != nil {
			p.liteCloseTimer.Stop()
			p.liteCloseTimer = nil
		}
		p.liteCloseDeadline.Store(time.Now().Add(-time.Nanosecond).UnixNano())
		p.mu.Unlock()

		var wg sync.WaitGroup
		errCh := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			p.liteCloseTick()
		}()
		go func() {
			defer wg.Done()
			fid := controller.Open(TrafficRealtime)
			tr, err := p.getTransportForClass(context.Background(), TrafficRealtime)
			if err != nil {
				errCh <- err
				controller.Close(fid)
				return
			}
			if tr.class != TrafficRealtime {
				errCh <- errors.New("reopen returned non-realtime transport")
			}
			tr.releaseStreamSlot()
			controller.Close(fid)
		}()
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				t.Fatalf("trial %d race error: %v", trial, err)
			}
		}
		_, _, liteCount, _ := poolClassCounts(p)
		if liteCount > 1 {
			t.Fatalf("trial %d has %d lite transports, want <=1", trial, liteCount)
		}
		_ = p.close()
	}
}

func TestPool_BulkRotationWhileLitePresent(t *testing.T) {
	p, _ := newClassTestPool(t, 10, 1, 2)
	p.topUp()
	bulk := findClassTransport(p, TrafficBulk)
	if bulk == nil {
		t.Fatal("missing bulk after topUp")
	}
	lite, err := p.getTransportForClass(context.Background(), TrafficRealtime)
	if err != nil {
		t.Fatalf("get realtime: %v", err)
	}
	defer lite.releaseStreamSlot()

	bulk.markDraining()
	_, err = p.getTransportForClass(context.Background(), TrafficBulk)
	if !errors.Is(err, ErrPoolBackpressure) {
		t.Fatalf("bulk get while draining+lite err = %v, want ErrPoolBackpressure", err)
	}

	p.cleanup()
	fresh, err := p.getTransportForClass(context.Background(), TrafficBulk)
	if err != nil {
		t.Fatalf("bulk get after cleanup: %v", err)
	}
	defer fresh.releaseStreamSlot()
	if fresh == bulk || fresh.class != TrafficBulk {
		t.Fatalf("fresh bulk = %p class %s, old=%p", fresh, fresh.class, bulk)
	}
}

func TestPool_BulkClassByteCapRotateNoLitePresent(t *testing.T) {
	p, created := newClassTestPool(t, 10, 1, 2)
	bulk, err := p.getTransportForClass(context.Background(), TrafficBulk)
	if err != nil {
		t.Fatalf("initial bulk: %v", err)
	}
	bulk.releaseStreamSlot()
	bulk.bytesSoftCap = 1
	bulk.addBytesSent(1)
	if !bulk.isDraining() {
		t.Fatal("bulk did not mark draining after byte cap")
	}
	fresh, err := p.getTransportForClass(context.Background(), TrafficBulk)
	if err != nil {
		t.Fatalf("fresh bulk after cap: %v", err)
	}
	fresh.releaseStreamSlot()
	if fresh == bulk {
		t.Fatal("byte-cap rotation reused draining bulk")
	}
	if got := created.Load(); got != 2 {
		t.Fatalf("created = %d, want 2", got)
	}
	if total, bulkCount, liteCount, _ := poolClassCounts(p); total != 2 || bulkCount != 2 || liteCount != 0 {
		t.Fatalf("pre-cleanup counts = %d/%d/%d, want 2/2/0", total, bulkCount, liteCount)
	}
	p.cleanup()
	if total, bulkCount, liteCount, _ := poolClassCounts(p); total != 1 || bulkCount != 1 || liteCount != 0 {
		t.Fatalf("post-cleanup counts = %d/%d/%d, want 1/1/0", total, bulkCount, liteCount)
	}
}

func TestPool_TopUpOnlyCreatesBulk(t *testing.T) {
	p, _ := newClassTestPool(t, 10, 1, 2)
	p.topUp()
	p.topUp()
	if total, bulk, lite, litePtr := poolClassCounts(p); total != 1 || bulk != 1 || lite != 0 || litePtr != nil {
		t.Fatalf("topUp counts total/bulk/lite/litePtr = %d/%d/%d/%p, want 1/1/0/nil", total, bulk, lite, litePtr)
	}
}

func TestPool_V1RotationOverlapAllowanceAllowsReplacement(t *testing.T) {
	p, created := newClassTestPool(t, 10, 1, 1, 1)
	bulk, err := p.getTransportForClass(context.Background(), TrafficBulk)
	if err != nil {
		t.Fatalf("initial bulk: %v", err)
	}
	bulk.releaseStreamSlot()
	bulk.bytesSoftCap = 1
	bulk.addBytesSent(1)
	if !bulk.isDraining() {
		t.Fatal("bulk did not mark draining after byte cap")
	}
	fresh, err := p.getTransportForClass(context.Background(), TrafficBulk)
	if err != nil {
		t.Fatalf("fresh bulk with overlap allowance: %v", err)
	}
	defer fresh.releaseStreamSlot()
	if fresh == bulk {
		t.Fatal("rotation reused draining bulk")
	}
	if got := created.Load(); got != 2 {
		t.Fatalf("created = %d, want 2", got)
	}
	if total, bulkCount, liteCount, _ := poolClassCounts(p); total != 2 || bulkCount != 2 || liteCount != 0 {
		t.Fatalf("overlap counts total/bulk/lite = %d/%d/%d, want 2/2/0", total, bulkCount, liteCount)
	}
	p.cleanup()
	if total, bulkCount, liteCount, _ := poolClassCounts(p); total != 1 || bulkCount != 1 || liteCount != 0 {
		t.Fatalf("post-cleanup counts = %d/%d/%d, want 1/1/0", total, bulkCount, liteCount)
	}
}

func TestPool_V1RotationOverlapZeroBackpressures(t *testing.T) {
	p, _ := newClassTestPool(t, 10, 1, 1, 0)
	bulk, err := p.getTransportForClass(context.Background(), TrafficBulk)
	if err != nil {
		t.Fatalf("initial bulk: %v", err)
	}
	bulk.releaseStreamSlot()
	bulk.bytesSoftCap = 1
	bulk.addBytesSent(1)
	if !bulk.isDraining() {
		t.Fatal("bulk did not mark draining after byte cap")
	}
	_, err = p.getTransportForClass(context.Background(), TrafficBulk)
	if !errors.Is(err, ErrPoolBackpressure) {
		t.Fatalf("fresh bulk with overlap 0 err = %v, want ErrPoolBackpressure", err)
	}
}
