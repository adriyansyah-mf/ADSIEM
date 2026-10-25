package tailer

import (
	"fmt"
	"testing"
	"time"
)

// An EvtNext batch is admitted in one group commit (a busy Security log is
// many events per flush, not one), in order; an unrenderable event in the
// middle is counted where it is, and the bookmark ends on the last event.
func TestDurableEventLogAdmitsABatchInGroupCommits(t *testing.T) {
	env := newTailEnv(t)
	ch := &fakeChannel{bad: map[int]bool{25: true}}
	useFakeChannel(t, ch)
	r := env.tailLog(nil)
	waitFor(t, "baseline", func() bool { _, ok := env.journal.Cursor(testChannelPath); return ok })
	records := make([]int, 50)
	for i := range records {
		records[i] = i + 1
	}
	began := time.Now()
	ch.write(records...)
	for len(r.cap.lines()) < 49 { // Windows runners are slow: allow time, report progress
		if time.Since(began) > time.Minute {
			t.Fatalf("after %s: %d of 49 events", time.Since(began), len(r.cap.lines()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("49 events admitted in %s", time.Since(began))
	r.stop(t)

	got := r.cap.lines()
	want := 1
	for _, line := range got {
		if want == 25 {
			want++ // unrenderable: counted, not admitted
		}
		if line != fmt.Sprintf("EventID=701 Record=%d", want) {
			t.Fatalf("got %q, want record %d", line, want)
		}
		want++
	}
	r.cap.mu.Lock()
	batches := append([]int(nil), r.cap.batches...)
	r.cap.mu.Unlock()
	if len(batches) > 4 {
		t.Fatalf("50 events took %d commits %v: not grouped", len(batches), batches)
	}
	if c, _ := env.journal.Cursor(testChannelPath); c.Bookmark != "bm:50" {
		t.Fatalf("bookmark %q after the batch", c.Bookmark)
	}
	if h := env.journal.Snapshot(); h.KnownLoss["source_failure"] != 1 {
		t.Fatalf("the unrenderable event is not counted: %+v", h.KnownLoss)
	}
}
