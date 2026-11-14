// agent/internal/task/heavy.go
package task

import (
	"runtime/debug"
	"sync"
)

// A YARA scan compiles the whole rule set (~46 MiB for the production set
// of 2,876 rules) and holds a chunk, its lowered copy and the prefilter's
// hit lists. On a small host (otakunesia: 956 MiB, no swap) two of them at
// once got the agent OOM-killed mid-scan, and its tasks never reported.
const heavyMemLimit = 256 << 20

var heavyMu sync.Mutex

// heavyScan runs one YARA scan at a time (file, memory, live-response
// memory: a second one waits for the first) under a soft Go memory limit,
// so the garbage collector returns each chunk's buffers before the next
// one instead of letting the heap grow.
func heavyScan[T any](fn func() (T, error)) (T, error) {
	heavyMu.Lock()
	defer heavyMu.Unlock()
	if prev := debug.SetMemoryLimit(-1); prev > heavyMemLimit {
		debug.SetMemoryLimit(heavyMemLimit)
		defer debug.SetMemoryLimit(prev)
	}
	return fn()
}
