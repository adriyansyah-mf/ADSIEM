// Package yarascan scans new and changed files with the YARA rules the
// server distributes, plus the hash and static ML hooks, and reports each
// match as a yara_match log line.
//
// Files reach it four ways:
//   - a watcher on the risky directories (temp folders, web roots, downloads);
//   - the file sensors (Linux eBPF, Windows ETW), for a program, script or
//     container written anywhere, with the process that wrote it;
//   - a program starting (ScanExec), ahead of everything else, and on Linux
//     the pre-exec check (CheckExec), which holds the exec until it answers;
//   - a rescan of recent files when the rules or known-malware hashes change.
//
// A match quarantines the file when the group policy says so (yara_action).
package yarascan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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

// Triggers: what made the scanner read a file (the line's trigger field).
const (
	TriggerOnAccess  = "on_access"
	TriggerExec      = "exec"       // a program started (scanned right after)
	TriggerExecCheck = "exec_check" // Linux: checked before the program may run
	TriggerRescan    = "rescan"     // rules or hashes changed
)

const (
	debounce       = 2 * time.Second
	maxRearm       = 15 // a file still being written is waited for, up to ~30 s
	hiQueue        = 2048
	loQueue        = 512
	maxPending     = 8192
	scanTimeout    = 30 * time.Second
	maxDepth       = 4
	maxWatchedDirs = 4096
	cacheEntries   = 20000
	rescanRoots    = 5 * time.Minute
	headProbe      = 16
)

// Rule is a rule source as the server sends it.
type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Revision string `json:"revision"` // of Content; matches name the revision that fired
}

// Writer is the process a file sensor saw write a file.
type Writer struct {
	PID   uint32
	Image string
}

// Options configure a Scanner.
type Options struct {
	// Roots are directories (or glob patterns) to watch recursively.
	Roots []string
	// MaxFileSize: larger files are hashed and only their head and tail
	// scanned (default 32 MiB).
	MaxFileSize int64
	// MaxPartialSize: files over MaxFileSize up to this size get the partial
	// scan; larger ones are skipped (default 512 MiB).
	MaxPartialSize int64
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
	// CacheFile keeps the last rule set from the server, loaded by New so
	// files are scanned with it until the server answers
	// (internal/rulecache). Empty: no cache.
	CacheFile string

	// Action is the group policy's answer for a YARA match in path:
	// "quarantine" with the lowest severity quarantined ("high" or
	// "critical"), or "detect". Nil: detect.
	Action func(path string) (action, minLevel string)
	// Quarantine locks a file (internal/task); a path inside a container
	// ("outer|inner") is the container's to lock.
	Quarantine func(path string) error
	// IsQuarantined reports a file the agent quarantined: CheckExec's answer.
	IsQuarantined func(path string) bool
	// OnQuarantined sees each file a YARA match quarantined, with the
	// process that wrote it when a sensor saw that (zero Writer otherwise);
	// it reports whether it stopped that writer (the dropper).
	OnQuarantined func(path string, w Writer) (writerStopped bool)
	// RescanAge: when the rules or known-malware hashes change, files in the
	// roots changed within this long are scanned again (default 7 days;
	// negative: never).
	RescanAge time.Duration
	// RescanMax caps the files one rescan reads (default 5000).
	RescanMax int
}

// Scanner owns the rule set, the watcher and the scan queue.
type Scanner struct {
	opts Options

	mu       sync.RWMutex
	rules    *yara.Rules
	hash     string
	ruleErrs []yara.SourceError
	refs     map[string]Rule // namespace (the server's rule name) -> its id and revision

	cacheMu sync.Mutex
	cache   map[string]string // path -> sha256 + rule hash + generation last scanned
	stats   map[string]statKey

	// gen changes when the known-malware hashes change: everything is new again
	gen atomic.Uint64

	hi, lo  chan job
	bg      chan job      // rescans: lowest priority, never lost
	dropped atomic.Int64  // since the last log line
	lost    atomic.Uint64 // since start: files never scanned (sensor_health)
	scanned atomic.Int64
	running atomic.Bool

	pendMu  sync.Mutex
	pending map[string]*pendingFile

	rescanMu     sync.Mutex
	rescanCancel context.CancelFunc
	runCtx       context.Context

	wantState
}

func New(opts Options) *Scanner {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 32 << 20
	}
	if opts.MaxPartialSize <= 0 {
		opts.MaxPartialSize = 512 << 20
	}
	if opts.MaxPartialSize < opts.MaxFileSize {
		opts.MaxPartialSize = opts.MaxFileSize
	}
	if opts.RescanAge == 0 {
		opts.RescanAge = 7 * 24 * time.Hour
	}
	if opts.RescanMax <= 0 {
		opts.RescanMax = 5000
	}
	if len(opts.Roots) == 0 {
		opts.Roots = DefaultRoots()
	}
	s := &Scanner{
		opts: opts, cache: map[string]string{}, stats: map[string]statKey{},
		hi: make(chan job, hiQueue), lo: make(chan job, loQueue), bg: make(chan job, 64),
		pending:   map[string]*pendingFile{},
		wantState: wantState{wake: make(chan struct{}, 1)},
	}
	s.LoadCache()
	return s
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
			drive + `\Users\*\Desktop`,
			drive + `\Users\*\AppData\Local\Temp`,
			drive + `\Users\Public`,
			drive + `\inetpub\wwwroot`,
		}
	}
	// Large trees (ProgramData, /root, /opt) are left to the file sensors:
	// watched recursively they would use up maxWatchedDirs.
	return []string{"/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv/www", "/home/*/Downloads"}
}

// Hash is the version of the loaded rule set ("" when none).
func (s *Scanner) Hash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hash
}

// SetRules compiles and swaps in a new rule set. Sources that do not
// compile are left out and returned. A new set rescans recent files.
func (s *Scanner) SetRules(hash string, rules []Rule) []yara.SourceError {
	srcs := make([]yara.Source, 0, len(rules))
	refs := make(map[string]Rule, len(rules))
	for _, r := range rules {
		srcs = append(srcs, yara.Source{Namespace: r.Name, Text: r.Content})
		refs[r.Name] = Rule{ID: r.ID, Name: r.Name, Revision: r.Revision}
	}
	compiled, errs := yara.CompileSources(srcs)
	s.mu.Lock()
	changed := s.hash != hash
	s.rules, s.hash, s.ruleErrs, s.refs = compiled, hash, errs, refs
	s.mu.Unlock()
	for _, e := range errs {
		slog.Warn("yara: rule does not compile, skipped", "rule", e.Namespace, "err", e.Err)
	}
	slog.Info("yara: rules loaded", "rules", compiled.Len(), "sources", len(rules), "errors", len(errs))
	if changed {
		s.rescan()
	}
	return errs
}

// Invalidate forgets which files were already checked (the known-malware
// hashes changed) and rescans recent files in the roots.
func (s *Scanner) Invalidate() {
	s.gen.Add(1)
	s.rescan()
}

func (s *Scanner) current() (*yara.Rules, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rules, s.hash
}

// Lost is the number of files the scanner had to leave unscanned since it
// started (a full queue): the sensor_health "lost" counter.
func (s *Scanner) Lost() uint64 { return s.lost.Load() }

// Run watches the roots and scans queued files until ctx ends.
func (s *Scanner) Run(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	watched := map[string]bool{}
	s.addRoots(w, watched)
	s.rescanMu.Lock()
	s.runCtx = ctx
	s.rescanMu.Unlock()
	s.running.Store(true)
	defer s.running.Store(false)
	go s.worker(ctx)
	s.rescan() // what was dropped while the agent was not running

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
			s.observe(ev.Name, Writer{}, false)
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

func (s *Scanner) roots() []string {
	var out []string
	for _, pattern := range s.opts.Roots {
		if strings.ContainsAny(pattern, "*?[") {
			m, _ := filepath.Glob(pattern)
			out = append(out, m...)
			continue
		}
		out = append(out, pattern)
	}
	return out
}

func (s *Scanner) addRoots(w *fsnotify.Watcher, watched map[string]bool) {
	for _, r := range s.roots() {
		if info, err := os.Stat(r); err == nil && info.IsDir() && !watched[r] {
			s.addTree(w, watched, r, 0)
			slog.Info("yara: watching", "root", r)
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

// ScanPath scans one file and pushes a line per matching rule. A file
// that has not changed since it was last scanned with the same rules is
// skipped.
func (s *Scanner) ScanPath(ctx context.Context, path, trigger string) ([]yara.RuleMatch, error) {
	matches, _, err := s.scan(ctx, job{path: path, trigger: trigger}, false)
	return matches, err
}

// Scan is ScanPath for scans run on request or on a schedule
// (internal/fullscan): force checks the file even when it is unchanged
// since the last check. It returns the number of detections: YARA matches
// and files the hooks reported, inside containers included.
func (s *Scanner) Scan(ctx context.Context, path, trigger string, force bool) (int, error) {
	m, hits, err := s.scan(ctx, job{path: path, trigger: trigger}, force)
	return len(m) + hits, err
}

// CheckExec is the Linux pre-exec check: path is about to run (via, when
// set, is where to read it: the fanotify event's descriptor). It scans the
// file now, with every engine, and reports whether it was quarantined, in
// which case the exec must be refused. A program the OS owns is not checked.
func (s *Scanner) CheckExec(ctx context.Context, path, via string) bool {
	if path == "" || SystemProgram(path) {
		return false
	}
	if _, _, err := s.scan(ctx, job{path: path, via: via, trigger: TriggerExecCheck}, false); err != nil {
		slog.Debug("yara: exec check skipped", "path", path, "err", err)
	}
	return s.opts.IsQuarantined != nil && s.opts.IsQuarantined(path)
}

// statKey is what a file looked like when it was last checked at exec.
type statKey struct {
	size  int64
	mtime int64
	key   string
}

// unchangedAtExec: a program that starts again unchanged since its last
// check is not read again (a busy host starts the same programs all day).
func (s *Scanner) unchangedAtExec(path string, info os.FileInfo, key string) bool {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	st, ok := s.stats[path]
	return ok && st.size == info.Size() && st.mtime == info.ModTime().UnixNano() && st.key == key
}

func (s *Scanner) rememberAtExec(path string, info os.FileInfo, key string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if len(s.stats) >= cacheEntries {
		s.stats = map[string]statKey{}
	}
	s.stats[path] = statKey{size: info.Size(), mtime: info.ModTime().UnixNano(), key: key}
}

// scanMeta travels with one file's scan to its lines.
type scanMeta struct {
	trigger string
	writer  Writer
	part    string // "head" or "tail" for a file too large to scan whole
}

func (s *Scanner) scan(ctx context.Context, j job, force bool) ([]yara.RuleMatch, int, error) {
	rules, hash := s.current()
	haveRules := rules != nil && rules.Len() > 0
	if !haveRules && s.opts.OnHash == nil && s.opts.OnData == nil {
		return nil, 0, nil
	}
	src := j.path
	if j.via != "" {
		src = j.via
	}
	var info os.FileInfo
	var err error
	if j.via != "" {
		info, err = os.Stat(src) // a descriptor link: the file behind it
	} else {
		info, err = os.Lstat(src)
	}
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, 0, nil
	}
	key := hash + "#" + strconv.FormatUint(s.gen.Load(), 10)
	atExec := j.trigger == TriggerExec || j.trigger == TriggerExecCheck
	if atExec && !force && s.unchangedAtExec(j.path, info, key) {
		return nil, 0, nil
	}
	if j.filter && !Interesting(j.path, readHead(src, headProbe)) {
		return nil, 0, nil
	}
	if info.Size() > s.opts.MaxFileSize {
		if info.Size() > s.opts.MaxPartialSize {
			return nil, 0, fmt.Errorf("larger than %d bytes", s.opts.MaxPartialSize)
		}
		m, hits, err := s.scanLarge(ctx, rules, haveRules, key, j, src, info.Size(), force)
		if err == nil && atExec {
			s.rememberAtExec(j.path, info, key)
		}
		return m, hits, err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if atExec {
		s.rememberAtExec(j.path, info, key)
	}
	if !s.markScanned(j.path, digest+key) && !force {
		return nil, 0, nil
	}
	yaraOn := haveRules && (s.opts.Skip == nil || !s.opts.Skip(j.path))
	meta := scanMeta{trigger: j.trigger, writer: j.writer}
	matches, hits, err := s.scanContent(ctx, rules, yaraOn, j.path, digest, data, meta)
	if err != nil {
		return matches, hits, err
	}
	// what is inside: archives, disk images, shortcuts, smuggled blobs
	if !s.opts.NoUnpack {
		res := unpack.Open(data, unpack.DefaultLimits)
		for _, n := range res.Notes {
			slog.Debug("unpack: left out", "path", j.path, "note", n)
		}
		for _, it := range res.Items {
			sum := sha256.Sum256(it.Data)
			inner := j.path + unpack.Sep + it.Path
			m, h, err := s.scanContent(ctx, rules, yaraOn, inner, hex.EncodeToString(sum[:]), it.Data, meta)
			if err != nil {
				slog.Debug("yara: inner scan failed", "path", inner, "err", err)
			}
			matches = append(matches, m...)
			hits += h
		}
	}
	return matches, hits, nil
}

// scanLarge handles a file over MaxFileSize: the whole file is hashed (the
// known-malware check), and its first MaxFileSize bytes and its last quarter
// of that are scanned. Padding a program to hundreds of megabytes, a common
// way past scanners with a size limit, leaves its code at the start.
func (s *Scanner) scanLarge(ctx context.Context, rules *yara.Rules, haveRules bool, key string, j job, src string,
	size int64, force bool) ([]yara.RuleMatch, int, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, 0, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if !s.markScanned(j.path, digest+key) && !force {
		return nil, 0, nil
	}
	hits := 0
	if s.opts.OnHash != nil && s.opts.OnHash(j.path, digest, size, j.trigger) {
		hits++
	}
	if !haveRules || (s.opts.Skip != nil && s.opts.Skip(j.path)) {
		return nil, hits, nil
	}
	head := s.opts.MaxFileSize
	tail := head / 4
	var matches []yara.RuleMatch
	for _, part := range []struct {
		name     string
		off, len int64
	}{{"head", 0, head}, {"tail", size - tail, tail}} {
		buf := make([]byte, part.len)
		n, err := f.ReadAt(buf, part.off)
		if n == 0 && err != nil {
			continue
		}
		m, _, err := s.matchAndReport(ctx, rules, j.path, digest, size, buf[:n],
			scanMeta{trigger: j.trigger, writer: j.writer, part: part.name})
		if err != nil {
			return matches, hits, err
		}
		matches = append(matches, m...)
	}
	return matches, hits, nil
}

// scanContent hands one file, or one file inside a container (path
// "outer|inner"), to the hash and data hooks and the YARA rules.
func (s *Scanner) scanContent(ctx context.Context, rules *yara.Rules, yaraOn bool, path, digest string, data []byte,
	meta scanMeta) ([]yara.RuleMatch, int, error) {
	hits := 0
	if s.opts.OnHash != nil && s.opts.OnHash(path, digest, int64(len(data)), meta.trigger) {
		hits++
	}
	if s.opts.OnData != nil && s.opts.OnData(path, digest, data, meta.trigger) {
		hits++
	}
	if !yaraOn {
		return nil, hits, nil
	}
	m, _, err := s.matchAndReport(ctx, rules, path, digest, int64(len(data)), data, meta)
	return m, hits, err
}

// matchAndReport runs the rules over data, applies the group policy's
// action to the file and pushes one line per match.
func (s *Scanner) matchAndReport(ctx context.Context, rules *yara.Rules, path, digest string, size int64, data []byte,
	meta scanMeta) ([]yara.RuleMatch, bool, error) {
	sctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	res, err := rules.Scan(sctx, data)
	if err != nil {
		return nil, false, err
	}
	s.scanned.Add(1)
	for _, w := range res.Warnings {
		slog.Warn("yara: scan limit hit", "path", path, "warning", w)
	}
	if len(res.Matches) == 0 {
		return nil, false, nil
	}
	action, qErr, stopped := "detected", "", false
	if s.shouldQuarantine(path, res.Matches) {
		if err := s.opts.Quarantine(path); err != nil {
			qErr = err.Error()
			slog.Warn("yara: match not quarantined", "path", path, "err", err)
		} else {
			action = "quarantined"
			if s.opts.OnQuarantined != nil {
				stopped = s.opts.OnQuarantined(path, meta.writer)
			}
		}
	}
	for _, m := range res.Matches {
		s.opts.Push(LogType, MatchLine(m, s.ref(m.Namespace), path, digest, size, meta.trigger)+
			outcome(action, qErr, meta, stopped))
		slog.Warn("yara: match", "rule", m.Rule, "namespace", m.Namespace, "path", path, "action", action)
	}
	return res.Matches, action == "quarantined", nil
}

// levelRank orders severities; unknown names rank like critical's floor.
var levelRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// shouldQuarantine: the group policy quarantines on YARA, and one of the
// matches is at least as severe as its threshold (default critical).
func (s *Scanner) shouldQuarantine(path string, matches []yara.RuleMatch) bool {
	if s.opts.Action == nil || s.opts.Quarantine == nil {
		return false
	}
	action, min := s.opts.Action(path)
	if action != "quarantine" {
		return false
	}
	floor, ok := levelRank[min]
	if !ok || floor < levelRank["high"] {
		floor = levelRank["critical"]
	}
	for _, m := range matches {
		if levelRank[Severity(m.Meta)] >= floor {
			return true
		}
	}
	return false
}

// outcome: what was done about the file, who wrote it, and which part of a
// large file matched (empty parts left out).
func outcome(action, err string, meta scanMeta, writerStopped bool) string {
	out := " action=" + action
	if err != "" {
		out += " error=" + kv(err)
	}
	if meta.writer.PID != 0 {
		out += fmt.Sprintf(" writer_pid=%d", meta.writer.PID)
	}
	if meta.writer.Image != "" {
		out += " writer_image=" + kv(meta.writer.Image)
	}
	if writerStopped {
		out += " writer_stopped=true"
	}
	if meta.part != "" {
		out += " part=" + meta.part
	}
	return out
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
