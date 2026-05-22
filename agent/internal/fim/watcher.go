package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
)

type Event struct {
	AgentID    string `json:"agent_id"`
	Path       string `json:"path"`
	EventType  string `json:"event_type"`
	SHA256     string `json:"sha256,omitempty"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	DetectedAt string `json:"detected_at"`
}

// Watcher manages the active fsnotify watcher and supports dynamic path updates.
type Watcher struct {
	agentID string
	c       *client.Client
	mu      sync.Mutex
	paths   []string
	fw      *fsnotify.Watcher
}

func Start(cfg *config.Config, c *client.Client) *Watcher {
	w := &Watcher{agentID: cfg.Agent.ID, c: c}
	if cfg.FIM.Enabled && len(cfg.FIM.WatchPaths) > 0 {
		w.startWatch(cfg.FIM.WatchPaths)
	}
	return w
}

// UpdatePaths is called by the heartbeat loop when the server sends new paths.
func (w *Watcher) UpdatePaths(newPaths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if pathsEqual(w.paths, newPaths) {
		return
	}
	slog.Info("fim: updating watch paths", "paths", newPaths)
	if w.fw != nil {
		w.fw.Close()
		w.fw = nil
	}
	w.paths = newPaths
	if len(newPaths) > 0 {
		w.startWatch(newPaths)
	}
}

// startWatch creates a new fsnotify watcher. Must be called with w.mu held.
func (w *Watcher) startWatch(paths []string) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("fim: failed to create watcher", "err", err)
		return
	}
	count := 0
	for _, p := range paths {
		count += addRecursive(fw, p)
	}
	w.fw = fw
	slog.Info("fim: started", "paths", paths, "dirs_watched", count)
	go run(w.agentID, w.c, fw)
}

func pathsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa, sb := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func hashFile(path string) (string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	h := sha256.New()
	n, _ := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n
}

func toEventType(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create != 0:
		return "CREATE"
	case op&fsnotify.Write != 0:
		return "MODIFY"
	case op&fsnotify.Remove != 0:
		return "DELETE"
	case op&fsnotify.Rename != 0:
		return "RENAME"
	default:
		return ""
	}
}

func isTempFile(name string) bool {
	base := filepath.Base(name)
	return strings.HasPrefix(base, ".") ||
		strings.HasSuffix(base, "~") ||
		strings.HasSuffix(base, ".swp") ||
		strings.HasSuffix(base, ".swx") ||
		strings.HasSuffix(base, ".tmp")
}

func addRecursive(w *fsnotify.Watcher, root string) int {
	count := 0
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if err := w.Add(path); err == nil {
			count++
		}
		return nil
	})
	return count
}

type pending struct {
	op    fsnotify.Op
	timer *time.Timer
}

func run(agentID string, c *client.Client, w *fsnotify.Watcher) {
	var (
		mu      sync.Mutex
		timers  = map[string]*pending{}
		batchMu sync.Mutex
		batch   []Event
	)

	flush := func() {
		batchMu.Lock()
		if len(batch) == 0 {
			batchMu.Unlock()
			return
		}
		toSend := batch
		batch = nil
		batchMu.Unlock()

		payload := map[string]any{"agent_id": agentID, "events": toSend}
		if err := c.PostWithRetry("/api/fim", payload, 2); err != nil {
			slog.Warn("fim: send failed", "err", err, "count", len(toSend))
		} else {
			slog.Info("fim: events sent", "count", len(toSend))
		}
	}

	enqueue := func(path string, op fsnotify.Op) {
		evType := toEventType(op)
		if evType == "" {
			return
		}
		ev := Event{
			AgentID:    agentID,
			Path:       path,
			EventType:  evType,
			DetectedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if evType == "CREATE" || evType == "MODIFY" {
			ev.SHA256, ev.SizeBytes = hashFile(path)
		}
		batchMu.Lock()
		batch = append(batch, ev)
		shouldFlush := len(batch) >= 50
		batchMu.Unlock()
		if shouldFlush {
			flush()
		}
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-w.Events:
			if !ok {
				flush()
				return
			}
			if isTempFile(event.Name) || event.Op == 0 {
				continue
			}
			if event.Op&fsnotify.Create != 0 {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					w.Add(event.Name)
				}
			}
			mu.Lock()
			if p, exists := timers[event.Name]; exists {
				p.op |= event.Op
				p.timer.Reset(2 * time.Second)
			} else {
				name := event.Name
				p := &pending{op: event.Op}
				p.timer = time.AfterFunc(2*time.Second, func() {
					mu.Lock()
					finalOp := p.op
					delete(timers, name)
					mu.Unlock()
					enqueue(name, finalOp)
				})
				timers[event.Name] = p
			}
			mu.Unlock()

		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			slog.Warn("fim: watcher error", "err", err)

		case <-ticker.C:
			flush()
		}
	}
}
