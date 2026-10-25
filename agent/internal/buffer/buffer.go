package buffer

import "sync"

type Buffer struct {
	mu      sync.Mutex
	items   []string
	cap     int
	sink    func(string) error
	dropped int64
	pushed  int64
	popped  int64
}

func New(capacity int) *Buffer {
	return &Buffer{items: make([]string, 0, capacity), cap: capacity}
}

// NewWithSink forwards offers without retaining entries. The sink defines
// admission semantics; in particular a bridge offer is not durable admission.
func NewWithSink(sink func(string) error) *Buffer {
	return &Buffer{sink: sink}
}

func (b *Buffer) Push(item string) {
	if b.sink != nil {
		// A detector invoked by the sink may reenter Push.
		err := b.sink(item)
		b.mu.Lock()
		b.pushed++
		if err != nil {
			b.dropped++
		}
		b.mu.Unlock()
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) >= b.cap {
		b.items = b.items[1:] // drop oldest
		b.dropped++
	}
	b.items = append(b.items, item)
	b.pushed++
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
