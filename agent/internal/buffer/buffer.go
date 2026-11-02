package buffer

import "sync"

// Buffer is the legacy in-memory delivery queue. Entries an urgency check
// marks (detections, prevention, sensor health) go to their own queue that
// is always drained first, so a detection never waits behind a backlog of
// telemetry; each queue drops its oldest entry when full.
type Buffer struct {
	mu       sync.Mutex
	items    []string
	urgent   []string
	isUrgent func(string) bool
	cap      int
	sink     func(string) error
	dropped  int64
	pushed   int64
	popped   int64
}

func New(capacity int) *Buffer {
	return &Buffer{items: make([]string, 0, capacity), cap: capacity}
}

// NewWithSink forwards offers without retaining entries. The sink defines
// admission semantics; in particular a bridge offer is not durable admission.
func NewWithSink(sink func(string) error) *Buffer {
	return &Buffer{sink: sink}
}

// SetUrgent sets which entries jump the queue (nil: none).
func (b *Buffer) SetUrgent(f func(entry string) bool) {
	b.mu.Lock()
	b.isUrgent = f
	b.mu.Unlock()
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
	b.pushed++
	if b.isUrgent != nil && b.isUrgent(item) {
		b.urgent = b.append(b.urgent, item)
		return
	}
	b.items = b.append(b.items, item)
}

// append adds to q, dropping its oldest entry when it is full.
func (b *Buffer) append(q []string, item string) []string {
	if b.cap > 0 && len(q) >= b.cap {
		q = q[1:]
		b.dropped++
	}
	return append(q, item)
}

func (b *Buffer) Stats() (int, int64, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items) + len(b.urgent), b.pushed, b.popped
}

func (b *Buffer) Pop() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pop()
}

func (b *Buffer) pop() (string, bool) {
	q := &b.items
	if len(b.urgent) > 0 {
		q = &b.urgent
	}
	if len(*q) == 0 {
		return "", false
	}
	item := (*q)[0]
	*q = (*q)[1:]
	b.popped++
	return item, true
}

// PopN takes up to n entries (urgent first) whose total length stays within
// maxBytes; the first entry is always taken, whatever its size.
func (b *Buffer) PopN(n, maxBytes int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	size := 0
	for len(out) < n {
		next := ""
		switch {
		case len(b.urgent) > 0:
			next = b.urgent[0]
		case len(b.items) > 0:
			next = b.items[0]
		default:
			return out
		}
		if len(out) > 0 && size+len(next) > maxBytes {
			return out
		}
		item, _ := b.pop()
		out = append(out, item)
		size += len(item)
	}
	return out
}

func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items) + len(b.urgent)
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
