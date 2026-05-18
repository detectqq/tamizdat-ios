package fragpoc

import "testing"

func TestDownWindowCountDefaults(t *testing.T) {
	for _, workers := range []int{1, 4, 8, 16, 64, 120} {
		if got := downWindowCount(workers, 0); got != 1 {
			t.Fatalf("downWindowCount(%d, 0) = %d, want 1", workers, got)
		}
	}
	if got := downWindowCount(64, 10); got != 10 {
		t.Fatalf("downWindowCount(64, 10) = %d, want 10", got)
	}
	if got := downWindowCount(64, MaxDownWindow+5); got != MaxDownWindow {
		t.Fatalf("downWindowCount(64, %d) = %d, want %d", MaxDownWindow+5, got, MaxDownWindow)
	}
	if got := downWindowCount(4, 10); got != downWorkerCount(workerCount(4)) {
		t.Fatalf("downWindowCount(4, 10) = %d, want down worker cap", got)
	}
}
