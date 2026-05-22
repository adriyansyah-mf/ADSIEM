package tailer

import (
	"log/slog"
	"sync"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/heartbeat"
)

type source struct {
	path    string
	logType string
	stopCh  chan struct{}
}

// Manager maintains a set of active tailers and hot-reloads on source changes.
type Manager struct {
	mu      sync.Mutex
	buf     *buffer.Buffer
	sources map[string]*source // key = path
}

func NewManager(buf *buffer.Buffer) *Manager {
	return &Manager{buf: buf, sources: make(map[string]*source)}
}

// Update starts/stops tailers to match the given sources list.
func (m *Manager) Update(sources []heartbeat.LogSource) {
	m.mu.Lock()
	defer m.mu.Unlock()

	wanted := make(map[string]heartbeat.LogSource)
	for _, s := range sources {
		if s.IsEnabled {
			wanted[s.Path] = s
		}
	}

	// Stop removed sources
	for path, active := range m.sources {
		if _, ok := wanted[path]; !ok {
			slog.Info("stopping tailer", "path", path)
			close(active.stopCh)
			delete(m.sources, path)
		}
	}

	// Start new sources
	for path, s := range wanted {
		if _, exists := m.sources[path]; !exists {
			slog.Info("starting tailer", "path", path, "type", s.LogType)
			stopCh := make(chan struct{})
			m.sources[path] = &source{path: path, logType: s.LogType, stopCh: stopCh}
			go Tail(path, s.LogType, m.buf, stopCh)
		}
	}
}

// StopAll stops all running tailers.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for path, active := range m.sources {
		slog.Info("stopping tailer", "path", path)
		close(active.stopCh)
	}
	m.sources = make(map[string]*source)
}
