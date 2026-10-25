// Package yarascan scans new and changed files in risky directories
// (temp folders, web roots, downloads) with the YARA rules the server
// distributes, and reports each match as a yara_match log line.
package yarascan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/siem-platform/agent/internal/yara"
)

// LogType is the log type of match lines (decoders/yara_match.yaml).
const LogType = "yara_match"

const (
	debounce       = 2 * time.Second
	queueSize      = 512
	scanTimeout    = 30 * time.Second
	maxDepth       = 4
	maxWatchedDirs = 4096
	cacheEntries   = 20000
	rescanRoots    = 5 * time.Minute
)

// Rule is a rule source as the server sends it.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// Options configure a Scanner.
type Options struct {
	// Roots are directories (or glob patterns) to watch recursively.
	Roots []string
	// MaxFileSize skips larger files.
	MaxFileSize int64
	// Push receives one encoded log line per match.
	Push func(logType, line string)
}

// Scanner owns the rule set and the on-access watcher.
type Scanner struct {
	opts Options

	mu       sync.RWMutex
	rules    *yara.Rules
	hash     string
	ruleErrs []yara.SourceError

	cacheMu sync.Mutex
	cache   map[string]string // path -> sha256 + rule hash last scanned

	queue   chan string
	dropped atomic.Int64
	scanned atomic.Int64

	wantState
}

func New(opts Options) *Scanner {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 32 << 20
	}
	if len(opts.Roots) == 0 {
		opts.Roots = DefaultRoots()
	}
	return &Scanner{
		opts: opts, cache: map[string]string{}, queue: make(chan string, queueSize),
		wantState: wantState{wake: make(chan struct{}, 1)},
	}
}

// DefaultRoots are the directories where dropped payloads and web shells
// usually land.
func DefaultRoots() []string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		return []string{
			filepath.Join(root, "Temp"),
			drive + `\Users\*\Downloads`,
			drive + `\Users\*\AppData\Local\Temp`,
			drive + `\Users\Public`,
			drive + `\inetpub\wwwroot`,
		}
	}
	return []string{"/tmp", "/var/tmp", "/dev/shm", "/var/www"}
}

// Hash is the version of the loaded rule set ("" when none).
func (s *Scanner) Hash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hash
}

// SetRules compiles and swaps in a new rule set. Sources that do not
// compile are left out and returned.
func (s *Scanner) SetRules(hash string, rules []Rule) []yara.SourceError {
	srcs := make([]yara.Source, 0, len(rules))
	for _, r := range rules {
		srcs = append(srcs, yara.Source{Namespace: r.Name, Text: r.Content})
	}
	compiled, errs := yara.CompileSources(srcs)
	s.mu.Lock()
	s.rules, s.hash, s.ruleErrs = compiled, hash, errs
	s.mu.Unlock()
	for _, e := range errs {
		slog.Warn("yara: rule does not compile, skipped", "rule", e.Namespace, "err", e.Err)
	}
	slog.Info("yara: rules loaded", "rules", compiled.Len(), "sources", len(rules), "errors", len(errs))
	return errs
}

func (s *Scanner) current() (*yara.Rules, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rules, s.hash
}

// Run watches the roots and scans queued files until ctx ends.
func (s *Scanner) Run(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	watched := map[string]bool{}
	s.addRoots(w, watched)
	go s.worker(ctx)

	var mu sync.Mutex
	timers := map[string]*time.Timer{}
	rescan := time.NewTicker(rescanRoots)
	defer rescan.Stop()
	report := time.NewTicker(10 * time.Minute)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write) == 0 {
				continue
			}
			if ev.Op&fsnotify.Create != 0 {
				if info, err := os.Lstat(ev.Name); err == nil && info.IsDir() {
					s.addTree(w, watched, ev.Name, depthOf(watched, ev.Name))
					continue
				}
			}
			name := ev.Name
			mu.Lock()
			if t, ok := timers[name]; ok {
				t.Reset(debounce)
			} else {
				timers[name] = time.AfterFunc(debounce, func() {
					mu.Lock()
					delete(timers, name)
					mu.Unlock()
					s.Enqueue(name)
				})
			}
			mu.Unlock()
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			slog.Warn("yara: watcher error", "err", err)
		case <-rescan.C:
			s.addRoots(w, watched)
		case <-report.C:
			if d := s.dropped.Swap(0); d > 0 {
				slog.Warn("yara: scan queue full, files skipped", "skipped", d)
			}
		}
	}
}

// Enqueue asks for path to be scanned; it is dropped when the queue is
// full rather than blocking the watcher.
func (s *Scanner) Enqueue(path string) {
	select {
	case s.queue <- path:
	default:
		s.dropped.Add(1)
	}
}

func (s *Scanner) addRoots(w *fsnotify.Watcher, watched map[string]bool) {
	for _, pattern := range s.opts.Roots {
		roots := []string{pattern}
		if strings.ContainsAny(pattern, "*?[") {
			roots, _ = filepath.Glob(pattern)
		}
		for _, r := range roots {
			if info, err := os.Stat(r); err == nil && info.IsDir() && !watched[r] {
				s.addTree(w, watched, r, 0)
				slog.Info("yara: watching", "root", r)
			}
		}
	}
}

// depthOf is the depth of a new directory below the nearest watched one.
func depthOf(watched map[string]bool, dir string) int {
	d := 0
	for p := filepath.Dir(dir); p != dir; dir, p = p, filepath.Dir(p) {
		d++
		if watched[p] {
			return d
		}
	}
	return maxDepth + 1
}

func (s *Scanner) addTree(w *fsnotify.Watcher, watched map[string]bool, root string, depth int) {
	base := strings.Count(filepath.Clean(root), string(filepath.Separator)) - depth
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Count(filepath.Clean(p), string(filepath.Separator))-base > maxDepth {
			return filepath.SkipDir
		}
		if len(watched) >= maxWatchedDirs {
			return filepath.SkipAll
		}
		if !watched[p] && w.Add(p) == nil {
			watched[p] = true
		}
		return nil
	})
}

func (s *Scanner) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-s.queue:
			if _, err := s.ScanPath(ctx, p, "on_access"); err != nil {
				slog.Debug("yara: scan skipped", "path", p, "err", err)
			}
		}
	}
}

// ScanPath scans one file and pushes a line per matching rule. A file
// that has not changed since it was last scanned with the same rules is
// skipped.
func (s *Scanner) ScanPath(ctx context.Context, path, trigger string) ([]yara.RuleMatch, error) {
	rules, hash := s.current()
	if rules == nil || rules.Len() == 0 {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, nil
	}
	if info.Size() > s.opts.MaxFileSize {
		return nil, fmt.Errorf("larger than %d bytes", s.opts.MaxFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if !s.markScanned(path, digest+hash) {
		return nil, nil
	}
	sctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	res, err := rules.Scan(sctx, data)
	if err != nil {
		return nil, err
	}
	s.scanned.Add(1)
	for _, w := range res.Warnings {
		slog.Warn("yara: scan limit hit", "path", path, "warning", w)
	}
	for _, m := range res.Matches {
		s.opts.Push(LogType, MatchLine(m, path, digest, int64(len(data)), trigger))
		slog.Warn("yara: match", "rule", m.Rule, "namespace", m.Namespace, "path", path)
	}
	return res.Matches, nil
}

func (s *Scanner) markScanned(path, key string) bool {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cache[path] == key {
		return false
	}
	if len(s.cache) >= cacheEntries {
		s.cache = map[string]string{}
	}
	s.cache[path] = key
	return true
}

// Severity maps rule metadata to an alert level: meta "severity" when it
// names a level, else "score" (0-100, signature-base style), else high.
func Severity(meta []yara.Meta) string {
	for _, m := range meta {
		if strings.EqualFold(m.Key, "severity") {
			if s, ok := m.Value.(string); ok {
				switch l := strings.ToLower(s); l {
				case "low", "medium", "high", "critical":
					return l
				}
			}
		}
	}
	for _, m := range meta {
		if !strings.EqualFold(m.Key, "score") {
			continue
		}
		var score int64
		switch v := m.Value.(type) {
		case int64:
			score = v
		case string:
			score, _ = strconv.ParseInt(v, 10, 64)
		}
		switch {
		case score >= 80:
			return "critical"
		case score >= 60:
			return "high"
		case score >= 40:
			return "medium"
		case score > 0:
			return "low"
		}
	}
	return "high"
}

func metaString(meta []yara.Meta, key string) string {
	for _, m := range meta {
		if strings.EqualFold(m.Key, key) {
			if s, ok := m.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

// kv quotes a value for the decoder's key="value" grammar.
func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	return `"` + s + `"`
}

// MatchLine encodes one rule match for decoders/yara_match.yaml.
func MatchLine(m yara.RuleMatch, path, sha string, size int64, trigger string) string {
	var strs []string
	seen := map[string]bool{}
	for _, sm := range m.Strings {
		if seen[sm.ID] || len(strs) >= 8 {
			continue
		}
		seen[sm.ID] = true
		strs = append(strs, fmt.Sprintf("%s@%d", sm.ID, sm.Offset))
	}
	sort.Strings(strs)
	return fmt.Sprintf("event=yara_match rule=%s namespace=%s severity=%s file=%s sha256=%s size=%d tags=%s strings=%s trigger=%s description=%s",
		kv(m.Rule), kv(m.Namespace), Severity(m.Meta), kv(path), sha, size,
		kv(strings.Join(m.Tags, ",")), kv(strings.Join(strs, ",")), trigger, kv(metaString(m.Meta, "description")))
}
