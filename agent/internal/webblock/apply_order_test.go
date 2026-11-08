package webblock

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// ApplyCurrent reads the list under the controller lock, so concurrent
// callers never leave an older list applied after a newer one.
func TestApplyCurrentLastAppliedIsNewest(t *testing.T) {
	c, _, _, _, _ := newCtl(t)
	var n atomic.Int64
	current := func() *List {
		v := n.Add(1)
		return listOf(fmt.Sprintf("g:%03d", v), "p", "evil.example")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.ApplyCurrent(current) }()
	}
	wg.Wait()
	if got, want := c.Health().Version, fmt.Sprintf("g:%03d", n.Load()); got != want {
		t.Fatalf("applied %q, newest %q", got, want)
	}
}

func TestControllerStopStopsServer(t *testing.T) {
	c, _, _, _, rec := newCtl(t)
	c.Stop()
	if rec.count("server.stop") != 1 {
		t.Fatal("server not stopped")
	}
}
