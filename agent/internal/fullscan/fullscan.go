// Package fullscan runs scans of the disk on request (dashboard "Scan now",
// task file_scan) or on the group policy's schedule: every file goes
// through the on-access scanner's engines (internal/yarascan: known-malware
// hashes and TLSH variants, YARA, static ML, and what is inside archives),
// so a scan finds what was on the disk before the agent, or before a hash
// or rule was known.
//
//   - quick: the folders malware is dropped in or started from (downloads,
//     temp, startup and autostart, web roots, cron and systemd units)
//   - full: every local disk (Linux: no pseudo or network file systems)
//   - custom: the paths given
//
// It runs at low priority (Linux: nice 19 and idle I/O class; Windows:
// background mode for its thread), reads at most Options.RateBytes a
// second, and leaves out what the group policy excludes and files the agent
// quarantined. One scan at a time.
package fullscan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogType of the progress and summary lines (decoders/file_scan.yaml).
const LogType = "file_scan"

// Kinds of scan.
const (
	KindQuick  = "quick"
	KindFull   = "full"
	KindCustom = "custom"
)

// ErrBusy: a scan is already running.
var ErrBusy = errors.New("a file scan is already running")

// Scanner is internal/yarascan's Scanner.
type Scanner interface {
	Scan(ctx context.Context, path, trigger string, force bool) (int, error)
}

// Options of one scan.
type Options struct {
	Kind  string
	Paths []string // custom only
	// RateBytes caps the bytes read a second (0: DefaultRate).
	RateBytes int64
	// MaxFileSize: larger files are not read (0: 32 MB).
	MaxFileSize int64
	// Skip, when set and true, leaves a file or directory out (exclusions,
	// quarantined files, the agent's own state).
	Skip func(path string) bool
	// Push receives the progress and summary lines.
	Push func(logType, line string)
	// Progress is how often a progress line goes out (0: a minute).
	Progress time.Duration
	// Requested: who asked ("schedule", "dashboard" or a task id).
	Requested string
}

// DefaultRate: 40 MB/s.
const DefaultRate = 40 << 20

// Summary of a finished scan.
type Summary struct {
	ScanID     string    `json:"scan_id"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"` // completed, cancelled
	Roots      []string  `json:"roots"`
	Files      int64     `json:"files"`
	Bytes      int64     `json:"bytes"`
	Detections int64     `json:"detections"`
	Errors     int64     `json:"errors"`
	Skipped    int64     `json:"skipped"`
	Started    time.Time `json:"started"`
	Duration   float64   `json:"duration_seconds"`
	Requested  string    `json:"requested,omitempty"`
}

var running sync.Mutex

// Running reports whether a scan is in progress.
func Running() bool {
	if running.TryLock() {
		running.Unlock()
		return false
	}
	return true
}

// Roots returns the directories a scan of kind walks.
func Roots(kind string, paths []string) []string {
	switch kind {
	case KindQuick:
		return expand(quickRoots())
	case KindFull:
		return fullRoots()
	}
	var out []string
	for _, p := range paths {
		if p = strings.TrimSpace(p); p != "" {
			if _, err := os.Stat(p); err == nil {
				out = append(out, filepath.Clean(p))
			}
		}
	}
	return out
}

// expand resolves glob patterns and drops what does not exist.
func expand(patterns []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if !seen[m] {
				if _, err := os.Stat(m); err == nil {
					seen[m] = true
					out = append(out, m)
				}
			}
		}
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Run scans; it returns ErrBusy when another scan runs.
func Run(ctx context.Context, sc Scanner, opts Options) (Summary, error) {
	if !running.TryLock() {
		return Summary{}, ErrBusy
	}
	defer running.Unlock()
	if opts.Kind == "" {
		opts.Kind = KindQuick
	}
	if opts.Kind != KindQuick && opts.Kind != KindFull && opts.Kind != KindCustom {
		return Summary{}, fmt.Errorf("unknown scan kind %q", opts.Kind)
	}
	if opts.RateBytes <= 0 {
		opts.RateBytes = DefaultRate
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 32 << 20
	}
	if opts.Progress <= 0 {
		opts.Progress = time.Minute
	}
	roots := Roots(opts.Kind, opts.Paths)
	if len(roots) == 0 {
		return Summary{}, errors.New("nothing to scan: no such paths")
	}
	trigger := opts.Kind + "_scan"
	s := Summary{ScanID: newID(), Kind: opts.Kind, Roots: roots, Started: time.Now().UTC(), Requested: opts.Requested}
	push := func(status string) {
		s.Status = status
		s.Duration = time.Since(s.Started).Seconds()
		if opts.Push != nil {
			opts.Push(LogType, s.line())
		}
	}
	push("started")
	slog.Info("file scan started", "id", s.ScanID, "kind", s.Kind, "roots", roots)

	// the scan's own thread at low CPU and I/O priority
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	restore := lowPriority()
	defer restore()

	lastProgress := time.Now()
	start := time.Now()
	skipFS := skippedMounts()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if path != root && (skipFS[path] || skipDir(path) || (opts.Skip != nil && opts.Skip(path))) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 {
				return nil
			}
			if info.Size() > opts.MaxFileSize || (opts.Skip != nil && opts.Skip(path)) {
				s.Skipped++
				return nil
			}
			n, err := sc.Scan(ctx, path, trigger, true)
			s.Files++
			s.Bytes += info.Size()
			s.Detections += int64(n)
			if err != nil && !errors.Is(err, context.Canceled) {
				s.Errors++
			}
			// stay under the read rate
			if want := time.Duration(float64(s.Bytes) / float64(opts.RateBytes) * float64(time.Second)); want > time.Since(start) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(want - time.Since(start)):
				}
			}
			if time.Since(lastProgress) >= opts.Progress {
				lastProgress = time.Now()
				push("running")
			}
			return nil
		})
		if err != nil && ctx.Err() != nil {
			push("cancelled")
			slog.Info("file scan cancelled", "id", s.ScanID, "files", s.Files)
			return s, nil
		}
	}
	push("completed")
	slog.Info("file scan finished", "id", s.ScanID, "kind", s.Kind, "files", s.Files, "detections", s.Detections,
		"seconds", int(s.Duration))
	return s, nil
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func (s Summary) line() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "event=file_scan status=%s scan_id=%s kind=%s files=%d bytes=%d detections=%d errors=%d skipped=%d duration=%.0f",
		s.Status, s.ScanID, s.Kind, s.Files, s.Bytes, s.Detections, s.Errors, s.Skipped, s.Duration)
	if s.Requested != "" {
		fmt.Fprintf(&sb, " requested=%s", kv(s.Requested))
	}
	fmt.Fprintf(&sb, " roots=%s", kv(strings.Join(s.Roots, ";")))
	return sb.String()
}
