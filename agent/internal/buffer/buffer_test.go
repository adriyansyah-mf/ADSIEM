package buffer

import (
	"testing"
	"time"
)

func TestOldestAge_EmptyBufferReportsNotOk(t *testing.T) {
	b := New(10)
	if _, ok := b.OldestAge(); ok {
		t.Fatal("expected ok=false for an empty buffer")
	}
}

func TestOldestAge_TracksTimeSinceFirstPendingItem(t *testing.T) {
	b := New(10)
	b.Push("first")
	time.Sleep(20 * time.Millisecond)
	b.Push("second")

	age, ok := b.OldestAge()
	if !ok {
		t.Fatal("expected ok=true once an item is queued")
	}
	if age < 15*time.Millisecond {
		t.Fatalf("expected age to reflect the first item's enqueue time (>=15ms), got %v", age)
	}
}

// TestOldestAge_ResetsOnEmptyToNonEmptyTransition proves the bug this test
// suite guards against: without resetting the timestamp when the buffer
// drains to empty, a later push would silently report a stale, inflated age
// carried over from a completely unrelated earlier item.
func TestOldestAge_ResetsOnEmptyToNonEmptyTransition(t *testing.T) {
	b := New(10)
	b.Push("old-item")
	time.Sleep(30 * time.Millisecond)
	if _, ok := b.Pop(); !ok {
		t.Fatal("expected to pop the item just pushed")
	}
	if _, ok := b.OldestAge(); ok {
		t.Fatal("expected ok=false immediately after draining to empty")
	}

	b.Push("fresh-item")
	age, ok := b.OldestAge()
	if !ok {
		t.Fatal("expected ok=true after pushing to a drained buffer")
	}
	if age > 15*time.Millisecond {
		t.Fatalf("expected a fresh age close to 0 after the empty->non-empty transition, got %v (stale timestamp not reset?)", age)
	}
}

func TestPush_DropsOldestWhenAtCapacity(t *testing.T) {
	b := New(2)
	b.Push("a")
	b.Push("b")
	b.Push("c") // capacity 2: "a" should be dropped

	depth, pushed, _ := b.Stats()
	if depth != 2 {
		t.Fatalf("expected depth 2 after exceeding capacity, got %d", depth)
	}
	if pushed != 3 {
		t.Fatalf("expected 3 total pushes recorded, got %d", pushed)
	}
	if b.Dropped() != 1 {
		t.Fatalf("expected 1 dropped item, got %d", b.Dropped())
	}
	first, _ := b.Pop()
	if first != "b" {
		t.Fatalf("expected oldest surviving item to be 'b' (\"a\" was dropped), got %q", first)
	}
}
