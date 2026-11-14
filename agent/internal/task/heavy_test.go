package task

import (
	"math"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two memory scans at once got otakunesia's agent OOM-killed: they run one
// after the other, each under the soft limit, which is put back afterwards.
func TestHeavyScanRunsOneAtATimeUnderTheLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(prev)

	var running, most atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = heavyScan(func() (int, error) {
				n := running.Add(1)
				for {
					m := most.Load()
					if n <= m || most.CompareAndSwap(m, n) {
						break
					}
				}
				if got := debug.SetMemoryLimit(-1); got != heavyMemLimit {
					t.Errorf("limit during a scan = %d, want %d", got, heavyMemLimit)
				}
				time.Sleep(20 * time.Millisecond)
				running.Add(-1)
				return 0, nil
			})
		}()
	}
	wg.Wait()
	if most.Load() != 1 {
		t.Fatalf("%d scans ran at once", most.Load())
	}
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Fatalf("limit after the scans = %d, want it restored", got)
	}
}

// A lower limit someone set (GOMEMLIMIT) is kept, not raised.
func TestHeavyScanKeepsALowerLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(64 << 20)
	defer debug.SetMemoryLimit(prev)
	_, _ = heavyScan(func() (int, error) {
		if got := debug.SetMemoryLimit(-1); got != 64<<20 {
			t.Errorf("limit = %d, want the lower one kept", got)
		}
		return 0, nil
	})
}
