// Package ransomguard detects ransomware from canary files and from bulk
// file activity, and stops it: the process tree is killed (and the host
// optionally isolated) when a canary is touched or the heuristics are
// confirmed by the entropy of the files the process wrote.
package ransomguard

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// LogType of detection lines (decoders/ransomware_activity.yaml).
const LogType = "ransomware_activity"

const verifyEvery = 30 * time.Second

// confirmRetry is the wait before a heuristic hit's files are sampled again.
const confirmRetry = 300 * time.Millisecond

// Options configure the Guard.
type Options struct {
	Push        func(logType, line string)
	CanaryDirs  []string // globs; empty means DefaultCanaryDirs
	CanaryNames []string
	// CanaryVisible plants canaries in plain sight (VisibleCanaryNames,
	// no hidden attribute on Windows) instead of hidden.
	CanaryVisible bool
	AllowImages   []string // basenames excluded from the heuristics
	// Kill stops the process tree on a canary hit or a confirmed
	// heuristic. Isolate, when set, also cuts the host off the network.
	Kill    bool
	Isolate func() error
	// IsolateFunc cuts the host off when the group policy asks for it
	// (Runtime.Isolate) though the local config does not.
	IsolateFunc func() error
}

// Runtime is what the group policy sets while the agent runs (internal/policy).
type Runtime struct {
	Off      bool // no reaction: canaries stay, nothing is reported or stopped
	Kill     bool // with the local Kill (report_only there wins)
	Isolate  bool // or the local isolate
	Excluded func(image string) bool
}

type Guard struct {
	opts Options
	can  *canaries
	rt   atomic.Pointer[Runtime]

	mu  sync.Mutex
	det *detector
	// response is the platform's kill; nil where there is none.
	response func(pid uint32) (killed int, err error)
}

func New(opts Options) *Guard {
	g := &Guard{
		opts:     opts,
		can:      newCanaries(opts.CanaryDirs, opts.CanaryNames, opts.CanaryVisible),
		det:      newDetector(opts.AllowImages),
		response: killTree,
	}
	g.rt.Store(&Runtime{Kill: true})
	return g
}

// Run plants the canaries and re-checks them until ctx ends. The check
// catches changes where no file events arrive (Windows, no eBPF).
func (g *Guard) Run(ctx context.Context) {
	n := g.can.plant()
	slog.Info("ransomguard: canaries planted", "files", n)
	t := time.NewTicker(verifyEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.checkCanaries()
		}
	}
}

// checkCanaries is the periodic check: changed canaries are reported and
// planted again. One that now looks encrypted is ransomware with no process
// known (it overwrote the canary between two checks without a file event):
// confirmed, so the critical rule fires, and the host is isolated when the
// configuration or the policy asks for it. Only clear-text changes and
// removals count toward retirement.
func (g *Guard) checkCanaries() {
	for _, c := range g.can.verify() {
		if c.encrypted {
			g.act(detection{kind: "canary_changed", canary: c.path, confirmed: true})
			continue
		}
		g.report(detection{kind: "canary_changed", canary: c.path})
		if g.can.strike(c.path) {
			g.report(detection{kind: "canary_retired", canary: c.path})
		}
	}
	g.can.plant()
}

// Observe takes one file event from the Linux sensor (or the Windows ETW
// sensor, adapted). It must stay cheap: entropy checks and responses run on
// their own goroutine.
func (g *Guard) Observe(ev linsensor.FileEvent) {
	rt := g.rt.Load()
	if rt.Off {
		return
	}
	for _, name := range []string{ev.Path, ev.From} {
		if name == "" {
			continue
		}
		if p, ok := g.can.canaryPath(name); ok {
			g.can.forget(p)
			go func() {
				g.act(detection{kind: "canary", pid: ev.PID, ppid: ev.PPID, uid: ev.UID, image: ev.Image,
					comm: ev.Comm, canary: p, action: ev.Action, confirmed: true})
				// Read once the process is stopped: what it left is final.
				// The new content is at Path (a write, or a rename of the
				// canary or over it); a delete leaves nothing to read.
				if ev.Action != "delete" && fileLooksEncrypted(ev.Path) {
					return // encryption: never a step toward retirement
				}
				if g.can.strike(p) {
					g.report(detection{kind: "canary_retired", canary: p, image: ev.Image, comm: ev.Comm,
						pid: ev.PID, ppid: ev.PPID, uid: ev.UID})
				}
			}()
			return
		}
	}
	if rt.Excluded != nil && rt.Excluded(ev.Image) {
		return // e.g. a backup tool the policy excludes: no heuristics
	}
	g.mu.Lock()
	f := g.det.observe(ev)
	g.mu.Unlock()
	if f == nil {
		return
	}
	go func() {
		ok, e := confirm(f.targets)
		if !ok {
			// The newest file may still be being written (on Linux the event
			// is the open): look once more before calling it benign.
			time.Sleep(confirmRetry)
			ok, e = confirm(f.targets)
		}
		sample := ""
		if len(f.targets) > 0 {
			sample = f.targets[len(f.targets)-1]
		}
		g.act(detection{kind: f.kind, pid: f.pid, ppid: f.ppid, uid: f.uid, image: f.image, comm: f.comm,
			files: f.files, ext: f.ext, sample: sample, entropy: e, confirmed: ok})
	}()
}

type detection struct {
	kind           string
	pid, ppid, uid uint32
	image, comm    string
	canary, action string
	files          int
	ext, sample    string
	entropy        float64
	confirmed      bool
	response       string
	killed         int
	isolated       bool
	err            string
}

// protectedImages are never killed (basenames, lower case). On Windows
// killTree also refuses critical system processes and the agent's ancestors.
var protectedImages = map[string]bool{"systemd": true, "init": true, "sshd": true, "siem-agent": true,
	"siem-agent.exe": true}

// SetRuntime applies the group policy.
func (g *Guard) SetRuntime(r Runtime) { g.rt.Store(&r) }

func (g *Guard) act(d detection) {
	d.response = "none"
	rt := g.rt.Load()
	excluded := d.pid != 0 && rt.Excluded != nil && rt.Excluded(d.image)
	// A confirmed detection without a process (the periodic check found a
	// canary encrypted) has nothing to kill: isolating is the only response.
	if g.opts.Kill && rt.Kill && !excluded && d.confirmed {
		switch {
		case d.pid == 0:
		case g.response == nil:
			d.response = "unsupported"
		case d.pid == 1 || protectedImages[strings.ToLower(filepath.Base(d.image))]:
			d.response = "kill_refused"
		default:
			n, err := g.response(d.pid)
			d.killed = n
			d.response = "killed"
			if err != nil {
				d.response, d.err = "kill_failed", err.Error()
			}
		}
		isolate := g.opts.Isolate
		if isolate == nil && rt.Isolate {
			isolate = g.opts.IsolateFunc
		}
		if isolate != nil {
			if err := isolate(); err != nil {
				d.err = strings.TrimSpace(d.err + " isolate: " + err.Error())
			} else {
				d.isolated = true
				if d.pid == 0 {
					d.response = "isolated"
				}
			}
		}
	}
	g.report(d)
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

func (d detection) line() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "detection=%s confirmed=%t response=%s", d.kind, d.confirmed, d.response)
	if d.canary != "" {
		fmt.Fprintf(&sb, " Canary=%s", kv(d.canary))
	}
	if d.action != "" {
		fmt.Fprintf(&sb, " FileAction=%s", d.action)
	}
	if d.files > 0 {
		fmt.Fprintf(&sb, " Files=%d", d.files)
	}
	if d.ext != "" {
		fmt.Fprintf(&sb, " Extension=%s", kv(d.ext))
	}
	if d.sample != "" {
		fmt.Fprintf(&sb, " TargetFilename=%s Entropy=%.2f", kv(d.sample), d.entropy)
	}
	if d.pid != 0 {
		fmt.Fprintf(&sb, " Image=%s Comm=%s PID=%d PPID=%d User=%d", kv(d.image), kv(d.comm), d.pid, d.ppid, d.uid)
	}
	if d.killed > 0 {
		fmt.Fprintf(&sb, " Killed=%d", d.killed)
	}
	fmt.Fprintf(&sb, " Isolated=%t", d.isolated)
	if d.err != "" {
		fmt.Fprintf(&sb, " Error=%s", kv(d.err))
	}
	return sb.String()
}

func (g *Guard) report(d detection) {
	if d.response == "" {
		d.response = "none"
	}
	g.opts.Push(LogType, d.line())
	slog.Warn("ransomguard: detection", "kind", d.kind, "pid", d.pid, "image", d.image,
		"confirmed", d.confirmed, "response", d.response)
}
