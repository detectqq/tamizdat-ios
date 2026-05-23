package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

var hex16Re = regexp.MustCompile(`\b[0-9a-f]{16}\b`)

func TestGenpoolMasterOutput(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		var buf bytes.Buffer
		if err := run([]string{"master"}, &buf); err != nil {
			t.Fatalf("run master: %v", err)
		}
		id := hex16Re.FindString(buf.String())
		if id == "" {
			t.Fatalf("no 16-hex shortID in output: %q", buf.String())
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate shortID after %d runs: %s", i+1, id)
		}
		seen[id] = struct{}{}
		if !strings.Contains(buf.String(), "--shortid "+id) || !strings.Contains(buf.String(), "tamizdat://"+id+"@host:port") {
			t.Fatalf("master output missing URI/cmdline hints: %q", buf.String())
		}
	}

	var buf bytes.Buffer
	if err := run(nil, &buf); err != nil {
		t.Fatalf("run default: %v", err)
	}
	if !hex16Re.MatchString(buf.String()) {
		t.Fatalf("default output did not emit master shortID: %q", buf.String())
	}
}

func TestGenpoolEpochOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"epoch"}, &buf); err != nil {
		t.Fatalf("run epoch: %v", err)
	}
	out := buf.String()
	re := regexp.MustCompile(`epoch_key:\s*(\S+)`)
	m := re.FindStringSubmatch(out)
	if len(m) != 2 {
		t.Fatalf("epoch_key line missing: %q", out)
	}
	epoch := m[1]
	if len(epoch) > 64 {
		t.Fatalf("epoch key len = %d, want <=64", len(epoch))
	}
	for i := 0; i < len(epoch); i++ {
		if epoch[i] >= 128 {
			t.Fatalf("epoch key contains non-ASCII byte: %q", epoch)
		}
	}
	if ok, _ := regexp.MatchString(`^ep-\d{4}-\d{2}-\d{2}-rotated-[0-9a-f]{8}$`, epoch); !ok {
		t.Fatalf("epoch key shape = %q", epoch)
	}
	if !strings.Contains(out, `"version":1`) || !strings.Contains(out, `"shortid_pool_size":100`) || !strings.Contains(out, epoch) {
		t.Fatalf("epoch output missing sample JSON: %q", out)
	}
}
