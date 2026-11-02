package buffer

import (
	"strings"
	"testing"
)

func urgent(s string) bool { return strings.HasPrefix(s, "!") }

func TestUrgentEntriesGoFirst(t *testing.T) {
	b := New(10)
	b.SetUrgent(urgent)
	for _, s := range []string{"a", "b", "!x", "c", "!y"} {
		b.Push(s)
	}
	if n, pushed, _ := b.Stats(); n != 5 || pushed != 5 || b.Len() != 5 {
		t.Fatalf("len=%d pushed=%d", n, pushed)
	}
	var got []string
	for {
		s, ok := b.Pop()
		if !ok {
			break
		}
		got = append(got, s)
	}
	if strings.Join(got, ",") != "!x,!y,a,b,c" {
		t.Fatalf("order %v", got)
	}
}

func TestPopNBoundsCountAndBytes(t *testing.T) {
	b := New(10)
	b.SetUrgent(urgent)
	for _, s := range []string{"aaaa", "bbbb", "!u", "cccc"} {
		b.Push(s)
	}
	if got := b.PopN(10, 7); strings.Join(got, ",") != "!u,aaaa" {
		t.Fatalf("bytes bound: %v", got)
	}
	if got := b.PopN(1, 1); strings.Join(got, ",") != "bbbb" {
		t.Fatalf("the first entry is taken whatever its size: %v", got)
	}
	if got := b.PopN(5, 100); strings.Join(got, ",") != "cccc" || b.Len() != 0 {
		t.Fatalf("rest: %v len=%d", got, b.Len())
	}
	if got := b.PopN(5, 100); got != nil {
		t.Fatalf("empty: %v", got)
	}
	if _, _, popped := b.Stats(); popped != 4 {
		t.Fatalf("popped %d", popped)
	}
}

func TestEachQueueDropsItsOldest(t *testing.T) {
	b := New(2)
	b.SetUrgent(urgent)
	for _, s := range []string{"a", "b", "c", "!x", "!y", "!z"} {
		b.Push(s)
	}
	if got := b.PopN(10, 100); strings.Join(got, ",") != "!y,!z,b,c" || b.Dropped() != 2 {
		t.Fatalf("%v dropped=%d", got, b.Dropped())
	}
}
