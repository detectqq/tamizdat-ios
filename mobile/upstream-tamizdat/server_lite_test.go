package tamizdat

import (
	"bytes"
	"net/http"
	"sync/atomic"
	"testing"
)

type countingHTTPWriter struct {
	header  http.Header
	writes  atomic.Int32
	flushes atomic.Int32
}

func (w *countingHTTPWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *countingHTTPWriter) Write(p []byte) (int, error) {
	w.writes.Add(1)
	return len(p), nil
}
func (w *countingHTTPWriter) WriteHeader(statusCode int) {}
func (w *countingHTTPWriter) Flush()                     { w.flushes.Add(1) }

func TestServerStreamConn_RealtimeSkipsFragmenter(t *testing.T) {
	w := &countingHTTPWriter{}
	sc := &serverStreamConn{
		writer:       flushWriter{w: w, flusher: w},
		shaper:       NewShaper(false, 0),
		fragmenter:   NewRecordFragmenter(true),
		trafficClass: TrafficRealtime,
	}
	payload := bytes.Repeat([]byte{'x'}, 256)
	n, err := sc.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write n/err = %d/%v, want %d/nil", n, err, len(payload))
	}
	if got := w.writes.Load(); got != 1 {
		t.Fatalf("realtime server writes = %d, want one direct write", got)
	}
	if got := w.flushes.Load(); got != 1 {
		t.Fatalf("realtime server flushes = %d, want one flush", got)
	}
}
