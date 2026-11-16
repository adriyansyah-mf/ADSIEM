package yarascan

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// job is one file to scan.
type job struct {
	path    string
	via     string // where to read it, when not path (a descriptor link)
	trigger string
	writer  Writer
	// filter: a file a sensor reported outside the roots, scanned only when
	// Interesting (by name or first bytes)
	filter bool
}

// pendingFile is a file waiting for its writes to settle.
type pendingFile struct {
	timer  *time.Timer
	writer Writer
	filter bool
	rearm  int
}

// observe schedules a scan of path once it has not been written for
// debounce. The watcher (filter false) and the sensors (filter true) share
// the schedule, so a file both report is scanned once, with its writer.
func (s *Scanner) observe(path string, w Writer, filter bool) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	if p, ok := s.pending[path]; ok {
		if w.PID != 0 {
			p.writer = w
		}
		p.filter = p.filter && filter
		p.timer.Reset(debounce)
		return
	}
	if len(s.pending) >= maxPending {
		s.drop(filter)
		return
	}
	p := &pendingFile{writer: w, filter: filter}
	p.timer = time.AfterFunc(debounce, func() { s.fire(path) })
	s.pending[path] = p
}

// fire queues a settled file. A file still growing (one open, a long
// download: a sensor reports the open, not each write) is waited for.
func (s *Scanner) fire(path string) {
	s.pendMu.Lock()
	p, ok := s.pending[path]
	if !ok {
		s.pendMu.Unlock()
		return
	}
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < debounce && p.rearm < maxRearm {
		p.rearm++
		p.timer.Reset(debounce)
		s.pendMu.Unlock()
		return
	}
	delete(s.pending, path)
	s.pendMu.Unlock()
	s.offer(job{path: path, trigger: TriggerOnAccess, writer: p.writer, filter: p.filter})
}

// ObserveFile is a file a sensor saw created, written or renamed into place
// anywhere on the host, with the process that did it. It is scanned like a
// file in a root when it looks like a program, script or container: by
// name now, by its first bytes when it is read. A no-op until Run starts.
func (s *Scanner) ObserveFile(path string, w Writer) {
	if !s.running.Load() || !SensorCandidate(path) {
		return
	}
	s.observe(path, w, true)
}

// ScanExec scans a program that just started, ahead of every other file
// (Windows: the ETW process start, as there is no veto before a program
// runs; Linux: the exec sensor, for what the pre-exec check did not see).
// A program the OS owns is left out. Quarantining it also stops it. via,
// when set, is where to read it (Linux: /proc/<pid>/exe, the program
// itself even when it runs in another mount namespace).
func (s *Scanner) ScanExec(path, via string) {
	if !s.running.Load() || path == "" || SystemProgram(path) {
		return
	}
	s.offer(job{path: path, via: via, trigger: TriggerExec})
}

// Enqueue asks for path to be scanned; it is dropped when the queue is
// full rather than blocking the caller, and counted as lost.
func (s *Scanner) Enqueue(path string) {
	s.offer(job{path: path, trigger: TriggerOnAccess})
}

// offer queues j: programs and scripts on the high-priority queue, the
// rest on the low one. A file from a sensor counts as a program only by its
// extension (a file without one, a browser cache entry for instance, waits
// on the low queue until its first bytes are read). A full queue loses the
// file.
func (s *Scanner) offer(j job) {
	q := s.lo
	if j.trigger == TriggerExec || (!j.filter && Runnable(j.path)) || (j.filter && RunnableName(j.path)) {
		q = s.hi
	}
	select {
	case q <- j:
	default:
		s.drop(j.filter)
	}
}

// drop counts a file left unscanned. One from the watched folders or a
// program starting is lost (sensor_health reports it: flooding a watched
// folder to hide a payload raises an alert); one a sensor reported from
// elsewhere is only logged, since a build or package install writes such
// bursts every day.
func (s *Scanner) drop(fromSensor bool) {
	s.dropped.Add(1)
	if !fromSensor {
		s.lost.Add(1)
	}
}

// worker scans queued files: programs and scripts first, then other new
// files, then rescans.
func (s *Scanner) worker(ctx context.Context) {
	for {
		if j, ok := s.next(); ok {
			s.do(ctx, j)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case j := <-s.hi:
			s.do(ctx, j)
		case j := <-s.lo:
			s.do(ctx, j)
		case j := <-s.bg:
			s.do(ctx, j)
		}
	}
}

// next takes a waiting job from the most urgent non-empty queue above bg.
func (s *Scanner) next() (job, bool) {
	select {
	case j := <-s.hi:
		return j, true
	default:
	}
	select {
	case j := <-s.lo:
		return j, true
	default:
	}
	return job{}, false
}

func (s *Scanner) do(ctx context.Context, j job) {
	if _, _, err := s.scan(ctx, j, false); err != nil {
		slog.Debug("yara: scan skipped", "path", j.path, "trigger", j.trigger, "err", err)
	}
}

// rescan scans the files in the roots changed within RescanAge again, at
// low priority, after the rules or known-malware hashes changed (and once
// when Run starts): a payload dropped yesterday is found by the rule that
// arrived today. A newer rescan replaces a running one. Nothing happens
// before Run.
func (s *Scanner) rescan() {
	if s.opts.RescanAge < 0 {
		return
	}
	s.rescanMu.Lock()
	defer s.rescanMu.Unlock()
	if s.runCtx == nil || s.runCtx.Err() != nil {
		return
	}
	if s.rescanCancel != nil {
		s.rescanCancel()
	}
	ctx, cancel := context.WithCancel(s.runCtx)
	s.rescanCancel = cancel
	go s.walkRecent(ctx)
}

// walkRecent feeds recent files to the rescan queue, waiting for room
// instead of dropping: a rescan is not an event that can be lost, and it
// never takes the place of one.
func (s *Scanner) walkRecent(ctx context.Context) {
	since := time.Now().Add(-s.opts.RescanAge)
	n := 0
	for _, root := range s.roots() {
		base := strings.Count(filepath.Clean(root), string(filepath.Separator))
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(filepath.Clean(p), string(filepath.Separator))-base > maxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.ModTime().Before(since) {
				return nil
			}
			if n >= s.opts.RescanMax {
				return filepath.SkipAll
			}
			n++
			select {
			case s.bg <- job{path: p, trigger: TriggerRescan}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
		if err != nil || n >= s.opts.RescanMax {
			break
		}
	}
	if n > 0 {
		slog.Info("yara: rescan of recent files queued", "files", n)
	}
}
