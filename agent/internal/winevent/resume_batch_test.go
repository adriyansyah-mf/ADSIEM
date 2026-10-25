package winevent

import (
	"context"
	"testing"
)

// One EvtNext batch reaches the caller at once, so it can be admitted in one
// group commit; each event still carries the bookmark just past it.
func TestSubscribeDeliversAnEvtNextBatchAtOnce(t *testing.T) {
	f := newFake(1, 2, 3, 4, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls [][]Event
	_ = subscribeResume(ctx, lockedFake{f}, "T", Resume{Empty: true, Initialized: true}, func(evs []Event) error {
		calls = append(calls, evs)
		cancel()
		return nil
	})
	if len(calls) != 1 || len(calls[0]) != 5 {
		t.Fatalf("batches %v", calls)
	}
	for i, ev := range calls[0] {
		if ev.RecordID != uint64(i+1) || ev.Bookmark == "" {
			t.Fatalf("event %d: %+v", i, ev)
		}
	}
	if leaks := f.leaks(); len(leaks) != 0 {
		t.Fatalf("leaked handles %v", leaks)
	}
}

// A bookmark failure mid-batch hands over the events before it, then stops:
// the caller resubscribes from its committed bookmark.
func TestBookmarkFailureMidBatchEmitsThePrefixFirst(t *testing.T) {
	f := newFake(1, 2, 3, 4, 5)
	f.badUpdate = map[uint64]bool{3: true}
	var calls [][]Event
	err := subscribeResume(context.Background(), lockedFake{f}, "T", Resume{Empty: true, Initialized: true}, func(evs []Event) error {
		calls = append(calls, evs)
		return nil
	})
	if err == nil {
		t.Fatal("a bookmark failure did not stop the subscription")
	}
	if len(calls) != 1 || len(calls[0]) != 2 || calls[0][1].RecordID != 2 {
		t.Fatalf("batches before the failure %v", calls)
	}
	if leaks := f.leaks(); len(leaks) != 0 {
		t.Fatalf("leaked handles %v", leaks)
	}
}
