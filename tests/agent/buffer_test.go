package agent_test

import (
	"testing"

	"github.com/siem-platform/agent/internal/buffer"
)

func TestBufferPushPop(t *testing.T) {
	b := buffer.New(3)
	b.Push("a")
	b.Push("b")
	item, ok := b.Pop()
	if !ok || item != "a" {
		t.Errorf("expected 'a', got %v (ok=%v)", item, ok)
	}
}

func TestBufferDropsOldestWhenFull(t *testing.T) {
	b := buffer.New(2)
	b.Push("a")
	b.Push("b")
	b.Push("c") // should drop "a"
	if b.Dropped() != 1 {
		t.Errorf("expected 1 dropped, got %d", b.Dropped())
	}
	item, _ := b.Pop()
	if item != "b" {
		t.Errorf("expected 'b' after drop, got %v", item)
	}
}

func TestBufferEmptyPop(t *testing.T) {
	b := buffer.New(5)
	_, ok := b.Pop()
	if ok {
		t.Error("expected ok=false on empty pop")
	}
}

func TestBufferLen(t *testing.T) {
	b := buffer.New(10)
	b.Push("x")
	b.Push("y")
	if b.Len() != 2 {
		t.Errorf("expected len 2, got %d", b.Len())
	}
}
