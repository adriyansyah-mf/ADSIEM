package buffer

import "sync"

type Buffer struct {
	mu      sync.Mutex
	items   []string
	cap     int
	dropped int64
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
	b.items = append(b.items, item)
}

func (b *Buffer) Pop() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return "", false
	}
	item := b.items[0]
	b.items = b.items[1:]
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
