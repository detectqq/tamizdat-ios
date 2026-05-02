package tamizdat

import (
	"io"
	"sync/atomic"
	"testing"
)

type countingRWC struct {
	writes atomic.Int32
	bytes  atomic.Int32
}

func (w *countingRWC) Read(p []byte) (int, error) { return 0, io.EOF }
func (w *countingRWC) Write(p []byte) (int, error) {
	w.writes.Add(1)
	w.bytes.Add(int32(len(p)))
	return len(p), nil
}
func (w *countingRWC) Close() error { return nil }

func TestStreamConn_LiteSkipsFragmenter(t *testing.T) {
	var mode atomic.Int32
	mode.Store(int32(ShapeLite))
	rwc := &countingRWC{}
	sc := newStreamConn(rwc, &streamAddr{"tcp", "local"}, &streamAddr{"tcp", "remote"}, "remote", NewShaper(false, 0), NewRecordFragmenter(true), &mode)
	payload := make([]byte, 256)
	n, err := sc.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write n/err = %d/%v, want %d/nil", n, err, len(payload))
	}
	if got := rwc.writes.Load(); got != 1 {
		t.Fatalf("lite writes = %d, want exactly one passthrough write", got)
	}
}

func TestStreamConn_FullPathStillFragments(t *testing.T) {
	var mode atomic.Int32
	mode.Store(int32(ShapeFull))
	rwc := &countingRWC{}
	sc := newStreamConn(rwc, &streamAddr{"tcp", "local"}, &streamAddr{"tcp", "remote"}, "remote", NewShaper(false, 0), NewRecordFragmenter(true), &mode)
	payload := make([]byte, 256)
	n, err := sc.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write n/err = %d/%v, want %d/nil", n, err, len(payload))
	}
	if got := rwc.writes.Load(); got <= 1 {
		t.Fatalf("full-shape writes = %d, want fragmentation to produce >1 writes", got)
	}
}
