package tailer

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/evidence"
	"github.com/siem-platform/agent/internal/heartbeat"
)

type source struct {
	path    string
	logType string
	stopCh  chan struct{}
	done    chan struct{} // closed when the source's goroutine returned
}

// Manager maintains a set of active tailers and hot-reloads on source changes.
// Update and StopAll return only after the sources they stop have finished.
type Manager struct {
	mu      sync.Mutex // serializes Update/StopAll; sources never take it
	run     func(path, logType string, stop <-chan struct{})
	sources map[string]*source // key = path
}

// NewManager tails into the legacy in-memory queue.
func NewManager(buf *buffer.Buffer) *Manager {
	return &Manager{sources: make(map[string]*source), run: func(path, logType string, stop <-chan struct{}) {
		if strings.HasPrefix(path, EventLogPrefix) {
			TailEventLog(path, logType, buf, stop)
		} else {
			Tail(path, logType, buf, stop)
		}
	}}
}

// NewDurableManager tails files and Windows event log channels into the
// journal from durable cursors (file offsets, event log bookmarks).
func NewDurableManager(j *evidence.Journal, p *evidence.Publisher) *Manager {
	return &Manager{sources: make(map[string]*source), run: func(path, logType string, stop <-chan struct{}) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		tail := TailDurable
		if strings.HasPrefix(path, EventLogPrefix) {
			tail = TailEventLogDurable
		}
		if err := tail(ctx, path, logType, j, p); err != nil {
			slog.Error("durable tailer stopped", "path", path, "err", err)
		}
	}}
}

// Update starts/stops tailers to match the given sources list. A path whose
// log type changed is restarted, so its events carry the new type.
func (m *Manager) Update(sources []heartbeat.LogSource) {
	m.mu.Lock()
	defer m.mu.Unlock()

	wanted := make(map[string]heartbeat.LogSource)
	for _, s := range sources {
		if s.IsEnabled {
			wanted[s.Path] = s
		}
	}

	var stopping []*source
	for path, active := range m.sources {
		if s, ok := wanted[path]; !ok || s.LogType != active.logType {
			slog.Info("stopping tailer", "path", path)
			stopping = append(stopping, active)
			delete(m.sources, path)
		}
	}
	m.join(stopping)

	for path, s := range wanted {
		if _, exists := m.sources[path]; !exists {
			slog.Info("starting tailer", "path", path, "type", s.LogType)
			m.sources[path] = m.start(path, s.LogType)
		}
	}
}

// StopAll stops all running tailers and waits for them.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	stopping := make([]*source, 0, len(m.sources))
	for path, active := range m.sources {
		slog.Info("stopping tailer", "path", path)
		stopping = append(stopping, active)
	}
	m.sources = make(map[string]*source)
	m.join(stopping)
}

func (m *Manager) start(path, logType string) *source {
	s := &source{path: path, logType: logType, stopCh: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		m.run(path, logType, s.stopCh)
	}()
	return s
}

// join signals every source first, then waits, so they stop in parallel.
func (m *Manager) join(sources []*source) {
	for _, s := range sources {
		close(s.stopCh)
	}
	for _, s := range sources {
		<-s.done
	}
}
