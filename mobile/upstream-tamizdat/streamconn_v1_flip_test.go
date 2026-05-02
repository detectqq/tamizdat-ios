package tamizdat

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestStreamConnV1WriteReadsLiveShapeMode(t *testing.T) {
	var mode atomic.Int32
	mode.Store(int32(ShapeFull))
	rwc := &countingRWC{}
	sc := newStreamConn(rwc, &streamAddr{"tcp", "local"}, &streamAddr{"tcp", "remote"}, "remote", NewShaper(false, 0), NewRecordFragmenter(true), &mode)

	payload := make([]byte, 256)
	if n, err := sc.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("full Write n/err = %d/%v, want %d/nil", n, err, len(payload))
	}
	fullWrites := rwc.writes.Load()
	if fullWrites <= 1 {
		t.Fatalf("full shape wrote %d chunks, want fragmentation >1", fullWrites)
	}

	mode.Store(int32(ShapeLite))
	if n, err := sc.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("lite Write n/err = %d/%v, want %d/nil", n, err, len(payload))
	}
	if delta := rwc.writes.Load() - fullWrites; delta != 1 {
		t.Fatalf("lite shape wrote %d chunks after flip, want exactly 1 passthrough write", delta)
	}
}

func TestStreamConnV1ConcurrentShapeFlipsAreAtomic(t *testing.T) {
	var mode atomic.Int32
	mode.Store(int32(ShapeFull))
	rwc := &countingRWC{}
	sc := newStreamConn(rwc, &streamAddr{"tcp", "local"}, &streamAddr{"tcp", "remote"}, "remote", nil, nil, &mode)
	payload := []byte("hello-v1-flip")

	var wg sync.WaitGroup
	start := make(chan struct{})
	errCh := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				n, err := sc.Write(payload)
				if err != nil {
					errCh <- err
					return
				}
				if n != len(payload) {
					errCh <- fmt.Errorf("short write: got %d want %d", n, len(payload))
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			if i%2 == 0 {
				mode.Store(int32(ShapeLite))
			} else {
				mode.Store(int32(ShapeFull))
			}
		}
	}()
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent write/flip error: %v", err)
		}
	}
	if got := rwc.bytes.Load(); got != int32(100*50*len(payload)) {
		t.Fatalf("bytes written = %d, want %d", got, 100*50*len(payload))
	}
}
