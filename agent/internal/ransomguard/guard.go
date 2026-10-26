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
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// LogType of detection lines (decoders/ransomware_activity.yaml).
const LogType = "ransomware_activity"

const verifyEvery = 30 * time.Second

// Options configure the Guard.
type Options struct {
	Push        func(logType, line string)
	CanaryDirs  []string // globs; empty means DefaultCanaryDirs
	CanaryNames []string
	AllowImages []string // basenames excluded from the heuristics
	// Kill stops the process tree on a canary hit or a confirmed
	// heuristic. Isolate, when set, also cuts the host off the network.
	Kill    bool
	Isolate func() error
}

type Guard struct {
	opts Options
	can  *canaries

	mu  sync.Mutex
	det *detector
	// response is the platform's kill; nil where there is none.
	response func(pid uint32) (killed int, err error)
}

func New(opts Options) *Guard {
	return &Guard{
		opts:     opts,
		can:      newCanaries(opts.CanaryDirs, opts.CanaryNames),
		det:      newDetector(opts.AllowImages),
		response: killTree,
	}
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
			for _, p := range g.can.verify() {
				g.report(detection{kind: "canary_changed", canary: p})
			}
			g.can.plant()
		}
	}
}

// Observe takes one file event from the Linux sensor. It must stay
// cheap: entropy checks and responses run on their own goroutine.
func (g *Guard) Observe(ev linsensor.FileEvent) {
	for _, p := range []string{ev.Path, ev.From} {
		if p != "" && g.can.isCanary(p) {
			g.can.forget(p)
			go g.act(detection{kind: "canary", pid: ev.PID, ppid: ev.PPID, uid: ev.UID, image: ev.Image,
				comm: ev.Comm, canary: p, action: ev.Action, confirmed: true})
			return
		}
	}
	g.mu.Lock()
	f := g.det.observe(ev)
	g.mu.Unlock()
	if f == nil {
		return
	}
	go func() {
		ok, e := confirm(f.targets)
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

// protectedImages are never killed.
var protectedImages = map[string]bool{"systemd": true, "init": true, "sshd": true, "siem-agent": true}

func (g *Guard) act(d detection) {
	d.response = "none"
	if g.opts.Kill && d.confirmed && d.pid != 0 {
		switch {
		case g.response == nil:
			d.response = "unsupported"
		case d.pid == 1 || protectedImages[filepath.Base(d.image)]:
			d.response = "kill_refused"
		default:
			n, err := g.response(d.pid)
			d.killed = n
			d.response = "killed"
			if err != nil {
				d.response, d.err = "kill_failed", err.Error()
			}
		}
		if g.opts.Isolate != nil {
			if err := g.opts.Isolate(); err != nil {
				d.err = strings.TrimSpace(d.err + " isolate: " + err.Error())
			} else {
				d.isolated = true
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
