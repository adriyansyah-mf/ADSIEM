package tailer

import (
	"fmt"
	"testing"
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
	ch.write(records...)
	waitFor(t, "49 renderable events", func() bool { return len(r.cap.lines()) == 49 })
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
