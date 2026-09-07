package buffer

import (
	"sync"
	"time"
)

type Buffer struct {
	mu      sync.Mutex
	items   []string
	cap     int
	dropped int64
	pushed  int64
	popped  int64
	// oldestQueuedAt is the enqueue time of whatever item has been sitting in
	// the buffer longest right now. Tracking a single timestamp (rather than
	// per-item timestamps) is a deliberately cheap approximation for P0-B
	// fleet-health telemetry — real per-item age tracking arrives with the
	// P0-A durable-spool rewrite, which restructures items into envelopes anyway.
	oldestQueuedAt time.Time
}

func New(capacity int) *Buffer {
	return &Buffer{items: make([]string, 0, capacity), cap: capacity}
}

func (b *Buffer) Push(item string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) >= b.cap {
		b.items = b.items[1:] // drop oldest
		b.dropped++
	}
	if len(b.items) == 0 {
		b.oldestQueuedAt = time.Now()
	}
	b.items = append(b.items, item)
	b.pushed++
}

// OldestAge returns how long the longest-queued item has been waiting, and
// whether the buffer is non-empty (a zero duration with ok=false means empty).
func (b *Buffer) OldestAge() (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return 0, false
	}
	return time.Since(b.oldestQueuedAt), true
}

// Stats returns (current length, total pushed, total popped) for diagnostics.
func (b *Buffer) Stats() (int, int64, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items), b.pushed, b.popped
}

func (b *Buffer) Pop() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return "", false
	}
	item := b.items[0]
	b.items = b.items[1:]
	b.popped++
	return item, true
}

func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

func (b *Buffer) Dropped() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

func (b *Buffer) ResetDropped() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.dropped
	b.dropped = 0
	return d
}
