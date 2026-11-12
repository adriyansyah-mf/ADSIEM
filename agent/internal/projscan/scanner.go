package projscan

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LogType of the lines this package writes.
const LogType = "project_scan"

// Defaults; Options override them (tests use small values).
const (
	defaultMaxFiles       = 5000             // files given to ScanFile (YARA) per project
	defaultMaxText        = 2 << 20          // bytes read of a file the checks look at
	defaultSettle         = 2 * time.Second  // a clone is polled this often ...
	defaultStablePeriods  = 3                // ... and scanned once this many polls in a row saw no change
	defaultMaxWait        = 10 * time.Minute // ... or after this long
	defaultMissingTimeout = 30 * time.Second // a clone whose directory never appears is dropped
	defaultEmptyTimeout   = 60 * time.Second // ... and one that never checks out a file (git init, a failed clone)
	defaultScanTimeout    = 10 * time.Minute // one project's scan
	defaultRescanHold     = 10 * time.Minute // the same directory isn't scanned again within this
	walkCap               = 50000            // entries walked looking for the files the checks know
	maxFindingLines       = 20
	queueSize             = 32
	maxWaiting            = 8 // clones waiting to finish at once
)

// skipDirs are never walked: git objects, installed dependencies (scanned by
// their own publishers' tooling, and far too many files), virtualenvs, caches.
var skipDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true, ".next": true, ".cache": true}

// Options configure a Scanner.
type Options struct {
	// ScanFile runs the agent's file scanner (YARA, known-malware hashes,
	// archives) on one file; its own lines report what it finds.
	ScanFile func(ctx context.Context, path string)
	// Emit writes a line (the agent's log buffer).
	Emit func(line string)
	// Excluded, if set, skips a project directory (policy exclusions).
	Excluded func(dir string) bool

	MaxFiles       int
	MaxText        int64
	Settle         time.Duration
	StablePeriods  int
	MaxWait        time.Duration
	MissingTimeout time.Duration
	EmptyTimeout   time.Duration
	ScanTimeout    time.Duration
	RescanHold     time.Duration
}

// Scanner takes triggers, waits for clones to finish (several at once), and
// scans one project at a time in the background.
type Scanner struct {
	opts    Options
	queue   chan Trigger
	waiting chan struct{} // slots for clones being waited on
	now     func() time.Time

	ctx    context.Context // ends when Run's context ends: stops the waits
	cancel context.CancelFunc

	mu     sync.Mutex
	recent map[string]time.Time
}

func New(opts Options) *Scanner {
	def := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultMaxFiles
	}
	if opts.MaxText <= 0 {
		opts.MaxText = defaultMaxText
	}
	if opts.StablePeriods <= 0 {
		opts.StablePeriods = defaultStablePeriods
	}
	def(&opts.Settle, defaultSettle)
	def(&opts.MaxWait, defaultMaxWait)
	def(&opts.MissingTimeout, defaultMissingTimeout)
	def(&opts.EmptyTimeout, defaultEmptyTimeout)
	def(&opts.ScanTimeout, defaultScanTimeout)
	def(&opts.RescanHold, defaultRescanHold)
	ctx, cancel := context.WithCancel(context.Background())
	return &Scanner{opts: opts, queue: make(chan Trigger, queueSize), waiting: make(chan struct{}, maxWaiting),
		now: time.Now, ctx: ctx, cancel: cancel, recent: map[string]time.Time{}}
}

// Offer takes a trigger; never blocks. The same directory is scanned at most
// once per RescanHold (npm install right after git clone, repeated installs).
// A clone is first waited on (in its own goroutine, so a clone that never
// finishes doesn't hold up the others).
func (s *Scanner) Offer(t Trigger) {
	if s == nil || t.Dir == "" {
		return
	}
	if !s.claim(t.Dir) {
		return
	}
	if t.Kind != "git_clone" {
		s.enqueue(t)
		return
	}
	select {
	case s.waiting <- struct{}{}:
		go func() {
			defer func() { <-s.waiting }()
			if s.settle(s.ctx, t.Dir) {
				s.enqueue(t)
			} else {
				s.release(t.Dir)
			}
		}()
	default:
		slog.Warn("project scan: too many clones in progress, skipping", "dir", t.Dir)
		s.release(t.Dir)
	}
}

func (s *Scanner) claim(dir string) bool {
	key := dirKey(dir)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if last, ok := s.recent[key]; ok && now.Sub(last) < s.opts.RescanHold {
		return false
	}
	s.recent[key] = now
	for d, at := range s.recent { // keep the map small
		if now.Sub(at) > s.opts.RescanHold {
			delete(s.recent, d)
		}
	}
	return true
}

// release forgets a directory that wasn't scanned, so its next trigger is.
func (s *Scanner) release(dir string) {
	s.mu.Lock()
	delete(s.recent, dirKey(dir))
	s.mu.Unlock()
}

// dirKey: Windows paths are case-insensitive, Linux ones aren't.
func dirKey(dir string) string {
	if windowsPath(dir) {
		return strings.ToLower(dir)
	}
	return dir
}

func (s *Scanner) enqueue(t Trigger) {
	select {
	case s.queue <- t:
	default:
		slog.Warn("project scan queue full, skipping", "dir", t.Dir)
		s.release(t.Dir)
	}
}

// Pending is how many projects wait to be scanned.
func (s *Scanner) Pending() int {
	if s == nil {
		return 0
	}
	return len(s.queue)
}

// InFlight is Pending plus the clones still being waited on.
func (s *Scanner) InFlight() int {
	if s == nil {
		return 0
	}
	return len(s.queue) + len(s.waiting)
}

// Run scans queued projects until ctx ends.
func (s *Scanner) Run(ctx context.Context) {
	defer s.cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-s.queue:
			if s.opts.Excluded != nil && s.opts.Excluded(t.Dir) {
				continue
			}
			// an install acts on its working directory: scan it only if that is a
			// project, never a home directory or / an IDE ran npm from
			if t.Kind != "git_clone" && !isProject(t.Dir) {
				s.release(t.Dir)
				continue
			}
			scanCtx, cancel := context.WithTimeout(ctx, s.opts.ScanTimeout)
			res := ScanDir(scanCtx, t.Dir, s.opts)
			if scanCtx.Err() == context.DeadlineExceeded {
				res.Truncated = true
			}
			cancel()
			for _, line := range Lines(t, res) {
				s.opts.Emit(line)
			}
		}
	}
}

// settle waits for a clone to finish: its checked-out files (outside .git)
// didn't change over StablePeriods polls in a row. git writes the objects
// first and checks the files out at the end, so a fetch that stalls doesn't
// look finished. False when ctx ended, the directory never appeared
// (MissingTimeout) or never got a file (EmptyTimeout: git init, a failed clone).
func (s *Scanner) settle(ctx context.Context, dir string) bool {
	start := s.now()
	prev, stable := [2]int64{-1, -1}, 0
	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(s.opts.Settle):
		}
		cur, exists := footprint(dir, s.opts.MaxFiles)
		elapsed := s.now().Sub(start)
		switch {
		case !exists:
			if elapsed > s.opts.MissingTimeout {
				return false
			}
			continue
		case cur[0] == 0:
			if elapsed > s.opts.EmptyTimeout {
				return false
			}
			continue
		}
		if cur == prev {
			if stable++; stable >= s.opts.StablePeriods-1 {
				return true
			}
		} else {
			stable = 0
		}
		prev = cur
		if elapsed > s.opts.MaxWait {
			return true // still changing after this long: scan what's there
		}
	}
}

// projectMarkers make a directory a project worth scanning on install.
var projectMarkers = []string{"package.json", "requirements.txt", "setup.py", "pyproject.toml"}

func isProject(dir string) bool {
	for _, m := range projectMarkers {
		if st, err := os.Stat(filepath.Join(dir, m)); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// footprint: count and size of the checked-out files (not .git, not
// dependencies), and whether the directory exists.
func footprint(dir string, limit int) ([2]int64, bool) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return [2]int64{}, false
	}
	var n, size int64
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if n++; n > int64(limit) {
			return filepath.SkipAll
		}
		if info, err := d.Info(); err == nil {
			size += info.Size()
		}
		return nil
	})
	return [2]int64{n, size}, true
}

// Result of one project scan.
type Result struct {
	Files     int // regular files found
	Truncated bool
	Findings  []Finding
}

type entry struct {
	path, rel string
	size      int64
}

// ScanDir walks a project. Every file the checks know (package.json,
// .vscode/tasks.json, JS, setup.py) is checked wherever it sits, so a pile of
// filler files can't push them out of reach; the first MaxFiles files go to
// ScanFile. Symlinks, FIFOs and devices are never opened.
func ScanDir(ctx context.Context, dir string, opts Options) Result {
	var res Result
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultMaxFiles
	}
	if opts.MaxText <= 0 {
		opts.MaxText = defaultMaxText
	}
	var files []entry
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p != dir && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(files) >= walkCap {
			res.Truncated = true
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		files = append(files, entry{p, filepath.ToSlash(rel), info.Size()})
		return nil
	})
	res.Files = len(files)
	for _, f := range files {
		if ctx.Err() != nil {
			break
		}
		if check := checkFor(f.rel); check != nil {
			res.Findings = append(res.Findings, runCheck(check, f, opts.MaxText)...)
		}
	}
	if opts.ScanFile != nil {
		for i, f := range files {
			if i >= opts.MaxFiles {
				res.Truncated = true
				break
			}
			if ctx.Err() != nil {
				res.Truncated = true
				break
			}
			opts.ScanFile(ctx, f.path)
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return rank(res.Findings[i].Severity) > rank(res.Findings[j].Severity)
	})
	return res
}

// runCheck reads at most maxText bytes. A manifest padded past that (to slip
// past the checks) is itself reported; JS is checked on its first maxText bytes.
func runCheck(check func(string, []byte) []Finding, f entry, maxText int64) []Finding {
	if f.size > maxText && !isJS(f.rel) {
		return []Finding{{"medium", "oversized_manifest", f.rel,
			fmt.Sprintf("unusually large (%d MiB), not parsed", f.size>>20)}}
	}
	fh, err := os.Open(f.path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxText))
	if err != nil {
		return nil
	}
	return check(f.rel, data)
}

func isJS(rel string) bool {
	n := strings.ToLower(rel)
	return strings.HasSuffix(n, ".js") || strings.HasSuffix(n, ".mjs") || strings.HasSuffix(n, ".cjs")
}

func checkFor(rel string) func(string, []byte) []Finding {
	name := strings.ToLower(filepath.Base(rel))
	switch {
	case name == "package.json":
		return CheckPackageJSON
	case name == "tasks.json" && strings.HasSuffix(strings.ToLower(rel), ".vscode/tasks.json"):
		return CheckVSCodeTasks
	case isJS(rel):
		return CheckJS
	case name == "setup.py":
		return CheckPythonSetup
	}
	return nil
}

func rank(sev string) int {
	switch sev {
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}

// Lines are what a scan reports: one summary (verdict clean or suspicious,
// what the user is told about) and one line per finding (what alerts).
func Lines(t Trigger, res Result) []string {
	severity, verdict, top := "none", "clean", ""
	if len(res.Findings) > 0 {
		severity, verdict = res.Findings[0].Severity, "suspicious"
		top = res.Findings[0].File + ": " + res.Findings[0].Detail
	}
	common := " trigger=" + t.Kind + " dir=" + q(t.Dir) + " origin=" + q(t.Origin) + " image=" + q(t.Image)
	lines := []string{"event=project_scan verdict=" + verdict + " severity=" + severity + common +
		" files=" + strconv.Itoa(res.Files) + " findings=" + strconv.Itoa(len(res.Findings)) +
		" truncated=" + strconv.FormatBool(res.Truncated) + " top=" + q(top)}
	for i, f := range res.Findings {
		if i == maxFindingLines {
			break
		}
		lines = append(lines, "event=project_scan_finding severity="+f.Severity+" check="+f.Check+common+
			" file="+q(f.File)+" detail="+q(f.Detail))
	}
	return lines
}

// q quotes a value; control characters become spaces first. File names come
// from the repository's author: one with newlines must not add lines of its
// own to the user's pop-up.
func q(s string) string {
	return strconv.Quote(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s))
}
