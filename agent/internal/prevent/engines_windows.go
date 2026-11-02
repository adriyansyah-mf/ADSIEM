//go:build windows

package prevent

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// The Windows engine decides after the fact: without a kernel driver nothing
// can veto a program before it runs, so the ETW sensor (internal/winsensor)
// hands every process start to ObserveExec, and a block rule terminates the
// process right away (action=terminated: it did run, briefly). Detect rules
// only report.

// HelperEnv marks the fanotify helper process (Linux only).
const HelperEnv = "SIEM_AGENT_FANOTIFY_HELPER"

func IsHelper() bool { return false }
func RunHelper() int { return 1 }

func init() { decisionLogType = WindowsLogType }

type windowsEngine struct {
	report func(Decision)
	self   uint32

	mu     sync.RWMutex
	policy *Policy

	hashes *hashCache
	work   chan struct{} // bounds concurrent hashing
}

func startEngines(report func(Decision)) (engines, error) {
	return &windowsEngine{report: report, self: uint32(os.Getpid()), hashes: newHashCache(4096),
		work: make(chan struct{}, 4)}, nil
}

func (e *windowsEngine) apply(p *Policy) {
	e.mu.Lock()
	e.policy = p
	e.mu.Unlock()
}

func (e *windowsEngine) close() {}

// observe runs off the sensor's goroutine: a hash rule reads the file.
func (e *windowsEngine) observe(ps ProcessStart) {
	e.mu.RLock()
	p := e.policy
	e.mu.RUnlock()
	if p == nil || !p.active() || ps.Image == "" || ps.PID == e.self || ps.PID <= 4 {
		return
	}
	go func() {
		e.work <- struct{}{}
		defer func() { <-e.work }()
		e.decide(p, ps)
	}()
}

func (e *windowsEngine) decide(p *Policy, ps ProcessStart) {
	var sum string
	c := p.Match(Exec{Path: ps.Image, Parent: ps.ParentImage, Hash: func() (string, bool) {
		h, err := e.hashes.get(ps.Image)
		sum = h
		return h, err == nil
	}}, false)
	if c == nil {
		return
	}
	d := Decision{Rule: c, Engine: "etw", Path: ps.Image, Parent: ps.ParentImage, SHA256: sum,
		Comm: filepath.Base(ps.Image), PID: ps.PID, PPID: ps.PPID}
	if c.block {
		if why := refuseKill(ps); why != "" {
			d.Error = why
		} else if err := terminate(ps.PID); err != nil {
			d.Error = err.Error()
		} else {
			d.Terminated = true
		}
	}
	if d.Error != "" {
		slog.Warn("prevent: block rule matched but the process was not terminated", "rule", c.Name,
			"image", ps.Image, "pid", ps.PID, "reason", d.Error)
	}
	e.report(d)
}

// refuseKill: never the System process, never a critical image running from
// the system directory (the guard keeps such rules detect-only, this also
// covers a hash or parent rule that happens to match one).
func refuseKill(ps ProcessStart) string {
	for _, p := range windowsProtected() {
		if strings.EqualFold(p, ps.Image) {
			return "protected Windows process " + filepath.Base(ps.Image)
		}
	}
	return ""
}

func terminate(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate pid %d: %w", pid, err)
	}
	return nil
}

// hashCache keeps executables' SHA-256 by path, size and modification time:
// the same program starts over and over.
type hashCache struct {
	mu  sync.Mutex
	max int
	m   map[string]hashEntry
}

type hashEntry struct {
	size  int64
	mtime time.Time
	sum   string
}

func newHashCache(max int) *hashCache { return &hashCache{max: max, m: map[string]hashEntry{}} }

func (h *hashCache) get(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	key := strings.ToLower(path)
	h.mu.Lock()
	if e, ok := h.m[key]; ok && e.size == st.Size() && e.mtime.Equal(st.ModTime()) {
		h.mu.Unlock()
		return e.sum, nil
	}
	h.mu.Unlock()
	sum, err := hashFile(path, 256<<20)
	if err != nil {
		return "", err
	}
	h.mu.Lock()
	if len(h.m) >= h.max {
		h.m = map[string]hashEntry{}
	}
	h.m[key] = hashEntry{size: st.Size(), mtime: st.ModTime(), sum: sum}
	h.mu.Unlock()
	return sum, nil
}
