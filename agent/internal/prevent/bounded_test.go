//go:build !windows

package prevent

import (
	"strings"
	"testing"
	"time"
)

// The Windows engine decides every process start through matchBounded. A
// path, directory or parent rule must be decided at once while every hashing
// slot is held by large files being hashed; only a hash rule waits.
func TestPathRulesDoNotWaitForHashingSlots(t *testing.T) {
	p, _ := compileWith([]Rule{
		{Name: "dir", RuleType: TypeDir, Value: "/dev/shm", Action: ActionBlock},
		{Name: "hash", RuleType: TypeHash, Value: strings.Repeat("ef", 32), Action: ActionBlock},
	}, testGuard)
	slots := make(chan struct{}, 4)
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{} // four 256 MB files being hashed
	}
	hashCalled := false
	hash := func(string) (string, error) { hashCalled = true; return strings.Repeat("ef", 32), nil }

	done := make(chan string, 1)
	go func() {
		c, _ := matchBounded(p, "/dev/shm/payload", "/bin/bash", slots, hash)
		if c == nil {
			done <- ""
			return
		}
		done <- c.Name
	}()
	select {
	case name := <-done:
		if name != "dir" || hashCalled {
			t.Fatalf("matched %q, hashed=%v", name, hashCalled)
		}
	case <-time.After(time.Second):
		t.Fatal("a directory rule waited for a hashing slot")
	}

	// a hash rule waits for a slot, then decides
	hashDone := make(chan string, 1)
	go func() {
		c, sum := matchBounded(p, "/tmp/z", "/bin/bash", slots, hash)
		if c == nil || sum == "" {
			hashDone <- ""
			return
		}
		hashDone <- c.Name
	}()
	select {
	case <-hashDone:
		t.Fatal("a hash rule did not wait for a slot")
	case <-time.After(50 * time.Millisecond):
	}
	<-slots // one hash finished
	select {
	case name := <-hashDone:
		if name != "hash" {
			t.Fatalf("hash rule matched %q", name)
		}
	case <-time.After(time.Second):
		t.Fatal("the hash rule never ran once a slot was free")
	}
	if len(slots) != cap(slots)-1 {
		t.Fatalf("slot not released: %d held", len(slots))
	}
}
