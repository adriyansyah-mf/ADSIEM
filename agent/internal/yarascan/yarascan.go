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
	"github.com/siem-platform/agent/internal/unpack"
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
	ID       string `json:"id"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Revision string `json:"revision"` // of Content; matches name the revision that fired
}

// Options configure a Scanner.
type Options struct {
	// Roots are directories (or glob patterns) to watch recursively.
	Roots []string
	// MaxFileSize skips larger files.
	MaxFileSize int64
	// Push receives one encoded log line per match.
	Push func(logType, line string)
	// OnHash, when set, gets every file read for scanning with its SHA-256
	// (the known-malware check, internal/malhash); files are then read even
	// with no YARA rules loaded.
	// trigger is ScanPath's (on_access, quick_scan, full_scan, ...); the
	// result says whether it reported the file (a detection).
	OnHash func(path, sha256 string, size int64, trigger string) bool
	// OnData, when set, gets the content of every file read for scanning,
	// after OnHash (the static ML check, internal/mlscan); like OnHash it
	// makes files be read with no YARA rules loaded. data must not be kept.
	OnData func(path, sha256 string, data []byte, trigger string) bool
	// Skip, when set and true for a file, leaves the YARA scan out (the
	// group policy turned on-access YARA off, or excludes the path); the
	// file still goes to OnHash.
	Skip func(path string) bool
	// NoUnpack leaves containers closed: by default what is inside an
	// archive, disk image, shortcut or smuggling page (internal/unpack) is
	// hashed, handed to OnData and scanned too, as "outer|inner" paths.
	NoUnpack bool
}

// Scanner owns the rule set and the on-access watcher.
type Scanner struct {
	opts Options

	mu       sync.RWMutex
	rules    *yara.Rules
	hash     string
	ruleErrs []yara.SourceError
	refs     map[string]Rule // namespace (the server's rule name) -> its id and revision

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
	refs := make(map[string]Rule, len(rules))
	for _, r := range rules {
		srcs = append(srcs, yara.Source{Namespace: r.Name, Text: r.Content})
		refs[r.Name] = Rule{ID: r.ID, Name: r.Name, Revision: r.Revision}
	}
	compiled, errs := yara.CompileSources(srcs)
	s.mu.Lock()
	s.rules, s.hash, s.ruleErrs, s.refs = compiled, hash, errs, refs
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
	matches, _, err := s.scan(ctx, path, trigger, false)
	return matches, err
}

// Scan is ScanPath for scans run on request or on a schedule
// (internal/fullscan): force checks the file even when it is unchanged
// since the last check. It returns the number of detections: YARA matches
// and files the hooks reported, inside containers included.
func (s *Scanner) Scan(ctx context.Context, path, trigger string, force bool) (int, error) {
	m, hits, err := s.scan(ctx, path, trigger, force)
	return len(m) + hits, err
}

func (s *Scanner) scan(ctx context.Context, path, trigger string, force bool) ([]yara.RuleMatch, int, error) {
	rules, hash := s.current()
	haveRules := rules != nil && rules.Len() > 0
	if !haveRules && s.opts.OnHash == nil && s.opts.OnData == nil {
		return nil, 0, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, 0, nil
	}
	if info.Size() > s.opts.MaxFileSize {
		return nil, 0, fmt.Errorf("larger than %d bytes", s.opts.MaxFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if !s.markScanned(path, digest+hash) && !force {
		return nil, 0, nil
	}
	yaraOn := haveRules && (s.opts.Skip == nil || !s.opts.Skip(path))
	matches, hits, err := s.scanContent(ctx, rules, yaraOn, path, digest, data, trigger)
	if err != nil {
		return matches, hits, err
	}
	// what is inside: archives, disk images, shortcuts, smuggled blobs
	if !s.opts.NoUnpack {
		res := unpack.Open(data, unpack.DefaultLimits)
		for _, n := range res.Notes {
			slog.Debug("unpack: left out", "path", path, "note", n)
		}
		for _, it := range res.Items {
			sum := sha256.Sum256(it.Data)
			inner := path + unpack.Sep + it.Path
			m, h, err := s.scanContent(ctx, rules, yaraOn, inner, hex.EncodeToString(sum[:]), it.Data, trigger)
			if err != nil {
				slog.Debug("yara: inner scan failed", "path", inner, "err", err)
			}
			matches = append(matches, m...)
			hits += h
		}
	}
	return matches, hits, nil
}

// scanContent hands one file, or one file inside a container (path
// "outer|inner"), to the hash and data hooks and the YARA rules.
func (s *Scanner) scanContent(ctx context.Context, rules *yara.Rules, yaraOn bool, path, digest string, data []byte,
	trigger string) ([]yara.RuleMatch, int, error) {
	hits := 0
	if s.opts.OnHash != nil && s.opts.OnHash(path, digest, int64(len(data)), trigger) {
		hits++
	}
	if s.opts.OnData != nil && s.opts.OnData(path, digest, data, trigger) {
		hits++
	}
	if !yaraOn {
		return nil, hits, nil
	}
	sctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	res, err := rules.Scan(sctx, data)
	if err != nil {
		return nil, hits, err
	}
	s.scanned.Add(1)
	for _, w := range res.Warnings {
		slog.Warn("yara: scan limit hit", "path", path, "warning", w)
	}
	for _, m := range res.Matches {
		s.opts.Push(LogType, MatchLine(m, s.ref(m.Namespace), path, digest, int64(len(data)), trigger))
		slog.Warn("yara: match", "rule", m.Rule, "namespace", m.Namespace, "path", path)
	}
	return res.Matches, hits, nil
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

// ScanBytes scans a buffer (a script's content) with the loaded rules:
// nothing when there are none. The scan stops after timeout.
func (s *Scanner) ScanBytes(ctx context.Context, data []byte) ([]yara.RuleMatch, error) {
	rules, _ := s.current()
	if rules == nil || rules.Len() == 0 || len(data) == 0 {
		return nil, nil
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := rules.Scan(sctx, data)
	if err != nil {
		return nil, err
	}
	return res.Matches, nil
}

// RuleName is the server's name for a match's namespace (its YARA rule set).
func (s *Scanner) RuleName(namespace string) string {
	if r := s.ref(namespace); r.Name != "" {
		return r.Name
	}
	return namespace
}

func (s *Scanner) ref(namespace string) Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refs[namespace]
}

// MatchLine encodes one rule match for decoders/yara_match.yaml. ref names the
// server's rule and revision; a rule drafted from a case carries it in meta.
func MatchLine(m yara.RuleMatch, ref Rule, path, sha string, size int64, trigger string) string {
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
		kv(strings.Join(m.Tags, ",")), kv(strings.Join(strs, ",")), trigger, kv(metaString(m.Meta, "description"))) +
		provenance(ref, metaString(m.Meta, "case"))
}

// provenance: the rule's id and revision, and the case it was drafted from (empty parts left out).
func provenance(ref Rule, caseID string) string {
	out := ""
	for _, f := range [][2]string{{"rule_id", ref.ID}, {"revision", ref.Revision}, {"case", caseID}} {
		if f[1] != "" {
			out += " " + f[0] + "=" + kv(f[1])
		}
	}
	return out
}
