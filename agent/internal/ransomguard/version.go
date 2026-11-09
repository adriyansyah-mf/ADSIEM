package ransomguard

import (
	"os"
	"sync"
	"time"
)

// nameCache remembers a per-file string (a PE OriginalFilename) by path,
// size and modification time: a file replaced in place is read again.
// Bounded.
type nameCache struct {
	read func(string) string
	mu   sync.Mutex
	m    map[string]nameEntry
}

type nameEntry struct {
	size  int64
	mtime time.Time
	name  string
}

const maxNameCache = 512

func newNameCache(read func(string) string) func(string) string {
	c := &nameCache{read: read, m: map[string]nameEntry{}}
	return c.get
}

func (c *nameCache) get(p string) string {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	c.mu.Lock()
	e, ok := c.m[p]
	c.mu.Unlock()
	if ok && e.size == info.Size() && e.mtime.Equal(info.ModTime()) {
		return e.name
	}
	n := c.read(p)
	c.mu.Lock()
	if len(c.m) >= maxNameCache {
		c.m = map[string]nameEntry{}
	}
	c.m[p] = nameEntry{size: info.Size(), mtime: info.ModTime(), name: n}
	c.mu.Unlock()
	return n
}
