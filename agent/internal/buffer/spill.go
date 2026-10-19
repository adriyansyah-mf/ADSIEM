package buffer

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const spillSuffixMarker = "\x1e"

type Spill struct {
	mu   sync.Mutex
	path string
	f    *os.File
	dead bool
}

func OpenSpill(path string) (*Spill, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Spill{path: path, f: f}, nil
}

// Append durably records an entry that could not be delivered. Entries are
// newline-separated; the codec payload uses \x00 but never \n, so a raw line
// is a safe record boundary as long as the message itself cannot contain one.
func (s *Spill) Append(entry string) {
	if s == nil || s.dead {
		return
	}
	line := strings.ReplaceAll(entry, "\n", spillSuffixMarker)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.f.WriteString(line + "\n"); err != nil {
		slog.Warn("spill write failed, disabling spill", "err", err)
		s.dead = true
	}
}

func (s *Spill) Count() int {
	if s == nil {
		return 0
	}
	f, err := os.Open(s.path)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	n := 0
	for sc.Scan() {
		n++
	}
	return n
}

// Drain returns every spilled entry and truncates the file. The caller must
// re-spill anything that still cannot be delivered.
func (s *Spill) Drain() []string {
	if s == nil || s.dead {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		out = append(out, strings.ReplaceAll(line, spillSuffixMarker, "\n"))
	}
	f.Close()

	if err := os.Truncate(s.path, 0); err != nil {
		slog.Warn("spill truncate failed", "err", err)
	}
	if _, err := s.f.Seek(0, 0); err != nil {
		slog.Warn("spill seek failed", "err", err)
	}
	return out
}

func (s *Spill) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		s.f.Close()
	}
}
