package buffer

import (
	"errors"
	"testing"
)

func TestSinkBufferNeverQueuesInMemory(t *testing.T) {
	// Given a sink which refuses durable admission.
	calls := 0
	b := NewWithSink(func(s string) error { calls++; return errors.New("disk full") })
	// When a non-replayable producer offers an entry.
	b.Push("syslog\x00line")
	// Then rejection is counted without a memory fallback.
	if calls != 1 || b.Len() != 0 || b.Dropped() != 1 {
		t.Fatal("hidden memory fallback or missing rejection")
	}
}

func TestSinkBufferAllowsReentrantPush(t *testing.T) {
	// Given a sink which emits another entry during admission.
	var b *Buffer
	b = NewWithSink(func(s string) error {
		if s == "original" {
			b.Push("local_detection")
		}
		return nil
	})
	// When admission reenters the buffer.
	b.Push("original")
	// Then both offers are counted without retained memory.
	length, pushed, popped := b.Stats()
	if length != 0 || pushed != 2 || popped != 0 || b.Dropped() != 0 {
		t.Fatalf("sink stats: %d %d %d", length, pushed, popped)
	}
}
