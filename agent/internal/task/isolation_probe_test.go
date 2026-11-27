package task

import (
	"testing"
	"time"
)

func TestIsolationProbeCachesNetsh(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	answer, ran := false, true
	p := &isolationProbe{
		check: func() (bool, bool) { calls++; return answer, ran },
		now:   func() time.Time { return now },
		ttl:   5 * time.Minute,
	}

	if v, ok := p.get(); v || !ok || calls != 1 {
		t.Fatalf("first get = %v,%v calls=%d", v, ok, calls)
	}
	now = now.Add(4 * time.Minute)
	answer = true // changed outside the agent: not seen before the TTL
	if v, _ := p.get(); v || calls != 1 {
		t.Fatalf("within TTL: got %v calls=%d, want cached false, 1 call", v, calls)
	}
	now = now.Add(time.Minute)
	if v, _ := p.get(); !v || calls != 2 {
		t.Fatalf("after TTL: got %v calls=%d, want true, 2 calls", v, calls)
	}

	answer = false
	p.invalidate() // the agent's own unisolate
	if v, _ := p.get(); v || calls != 3 {
		t.Fatalf("after invalidate: got %v calls=%d, want false, 3 calls", v, calls)
	}

	p.invalidate()
	ran = false // netsh did not run: unknown, and not cached
	if _, ok := p.get(); ok || calls != 4 {
		t.Fatalf("failed check: ok=%v calls=%d", ok, calls)
	}
	ran = true
	if _, ok := p.get(); !ok || calls != 5 {
		t.Fatalf("retry after failure: ok=%v calls=%d", ok, calls)
	}
}
