package fragpoc

import (
	"sync"
	"testing"
	"time"
)

func newTestScheduler(conn *Conn, downWindow int) *downScheduler {
	s := &downScheduler{
		client: &Client{downWindow: downWindow},
		active: map[*Conn]struct{}{
			conn: {},
		},
		conns: []*Conn{conn},
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func finishScheduledPoll(s *downScheduler, conn *Conn, outcome downPollOutcome) {
	conn.schedInFlight = 1
	s.finish(conn, outcome)
}

func TestSchedulerDataSlowStartsThenAddsWindow(t *testing.T) {
	conn := &Conn{schedWindow: 1, schedInFlight: 1}
	s := newTestScheduler(conn, 10)

	s.finish(conn, downPollData)
	if conn.schedWindow != 2 {
		t.Fatalf("schedWindow after first data = %d, want 2", conn.schedWindow)
	}
	finishScheduledPoll(s, conn, downPollData)
	if conn.schedWindow != 4 {
		t.Fatalf("schedWindow after second data = %d, want 4", conn.schedWindow)
	}
	finishScheduledPoll(s, conn, downPollData)
	if conn.schedWindow != 8 {
		t.Fatalf("schedWindow after third data = %d, want 8", conn.schedWindow)
	}
	finishScheduledPoll(s, conn, downPollData)
	if conn.schedWindow != 9 {
		t.Fatalf("schedWindow after fourth data = %d, want 9", conn.schedWindow)
	}
	if conn.schedInFlight != 0 {
		t.Fatalf("schedInFlight after finish = %d, want 0", conn.schedInFlight)
	}
	if conn.schedLastPayload.IsZero() {
		t.Fatal("schedLastPayload was not updated on data")
	}
}

func TestSchedulerDataCapsAtDownWindow(t *testing.T) {
	conn := &Conn{schedWindow: 4, schedInFlight: 1}
	s := newTestScheduler(conn, 6)

	s.finish(conn, downPollData)

	if conn.schedWindow != 6 {
		t.Fatalf("schedWindow after capped data = %d, want 6", conn.schedWindow)
	}
}

func TestSchedulerRecentTransientReducesWithFloor(t *testing.T) {
	now := time.Now()
	conn := &Conn{
		schedWindow:       9,
		schedInFlight:     1,
		schedLastProgress: now,
		schedLastPayload:  now.Add(-200 * time.Millisecond),
		schedErrorDelay:   schedulerErrorInitial,
	}
	s := newTestScheduler(conn, 10)

	s.finish(conn, downPollTransient)

	if conn.schedWindow != 4 {
		t.Fatalf("schedWindow after transient = %d, want 4", conn.schedWindow)
	}
	if conn.schedNextPoll.IsZero() {
		t.Fatal("schedNextPoll was not set after transient")
	}
	if conn.schedErrorDelay <= schedulerErrorInitial {
		t.Fatalf("schedErrorDelay = %s, want grown beyond %s", conn.schedErrorDelay, schedulerErrorInitial)
	}

	conn.schedWindow = 2
	conn.schedInFlight = 1
	conn.schedLastProgress = time.Now()
	conn.schedLastPayload = time.Now().Add(-200 * time.Millisecond)
	conn.schedErrorDelay = schedulerErrorInitial
	s.finish(conn, downPollTransient)

	if conn.schedWindow != 2 {
		t.Fatalf("schedWindow after recent transient at floor = %d, want 2", conn.schedWindow)
	}
}

func TestSchedulerTransientWithoutPayloadCollapses(t *testing.T) {
	conn := &Conn{
		schedWindow:       9,
		schedInFlight:     1,
		schedLastProgress: time.Now(),
		schedErrorDelay:   schedulerErrorInitial,
	}
	s := newTestScheduler(conn, 10)

	s.finish(conn, downPollTransient)

	if conn.schedWindow != 1 {
		t.Fatalf("schedWindow after transient without payload = %d, want 1", conn.schedWindow)
	}
}

func TestSchedulerRecentIdleReducesWithFloorWithoutBackoff(t *testing.T) {
	now := time.Now()
	conn := &Conn{
		schedWindow:      8,
		schedInFlight:    1,
		schedLastPayload: now.Add(-200 * time.Millisecond),
		schedIdleDelay:   schedulerIdleInitial,
	}
	s := newTestScheduler(conn, 10)

	s.finish(conn, downPollIdle)

	if conn.schedWindow != 4 {
		t.Fatalf("schedWindow after recent idle = %d, want 4", conn.schedWindow)
	}
	if time.Since(conn.schedNextPoll) > 50*time.Millisecond {
		t.Fatalf("schedNextPoll after recent idle = %s, want immediate", conn.schedNextPoll)
	}
	if conn.schedIdleDelay != schedulerIdleInitial {
		t.Fatalf("schedIdleDelay after recent idle = %s, want %s", conn.schedIdleDelay, schedulerIdleInitial)
	}

	conn.schedWindow = 2
	conn.schedInFlight = 1
	conn.schedLastPayload = time.Now().Add(-200 * time.Millisecond)
	s.finish(conn, downPollIdle)

	if conn.schedWindow != 2 {
		t.Fatalf("schedWindow after recent idle at floor = %d, want 2", conn.schedWindow)
	}
}

func TestSchedulerOldIdleCollapsesAndBacksOff(t *testing.T) {
	conn := &Conn{
		schedWindow:      8,
		schedInFlight:    1,
		schedLastPayload: time.Now().Add(-2 * schedulerRecentData),
		schedIdleDelay:   schedulerIdleInitial,
	}
	s := newTestScheduler(conn, 10)

	s.finish(conn, downPollIdle)

	if conn.schedWindow != 1 {
		t.Fatalf("schedWindow after old idle = %d, want 1", conn.schedWindow)
	}
	if !conn.schedNextPoll.After(time.Now()) {
		t.Fatalf("schedNextPoll after old idle = %s, want future backoff", conn.schedNextPoll)
	}
	if conn.schedIdleDelay <= schedulerIdleInitial {
		t.Fatalf("schedIdleDelay after old idle = %s, want grown beyond %s", conn.schedIdleDelay, schedulerIdleInitial)
	}
}

func TestSchedulerStatsReportsWindow(t *testing.T) {
	connA := &Conn{schedWindow: 3, schedInFlight: 1}
	connB := &Conn{schedWindow: 7, schedInFlight: 2}
	s := &downScheduler{
		client: &Client{downWorkers: 96},
		active: map[*Conn]struct{}{
			connA: {},
			connB: {},
		},
		conns: []*Conn{connA, connB},
	}
	s.cond = sync.NewCond(&s.mu)

	active, queued, inFlight, windowCur, windowMax, inflightCap := s.stats()

	if active != 2 || queued != 2 || inFlight != 3 {
		t.Fatalf("stats active/queued/inFlight = %d/%d/%d, want 2/2/3", active, queued, inFlight)
	}
	if windowCur != 3 || windowMax != 7 {
		t.Fatalf("stats windowCur/windowMax = %d/%d, want 3/7", windowCur, windowMax)
	}
	if inflightCap != 67 {
		t.Fatalf("stats inflightCap = %d, want 67", inflightCap)
	}
}

func TestSchedulerMaxInflight(t *testing.T) {
	tests := []struct {
		workers int
		want    int
	}{
		{workers: 0, want: 1},
		{workers: 8, want: 8},
		{workers: 24, want: 16},
		{workers: 96, want: 67},
	}
	for _, tt := range tests {
		s := &downScheduler{client: &Client{downWorkers: tt.workers}}
		if got := s.maxInflight(); got != tt.want {
			t.Fatalf("maxInflight(%d) = %d, want %d", tt.workers, got, tt.want)
		}
	}
}
