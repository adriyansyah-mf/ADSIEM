// Package ioa finds indicators of attack: ordered chains of behaviour in a
// process tree (an Office app starts PowerShell, which then reaches the
// internet; a web server's shell runs recon; a file a downloader wrote is
// executed). It reads the sensor lines the agent already produces (Windows
// ETW, Linux eBPF) and reports a chain once every step of a rule was seen.
//
// Detect only for now: a match is reported (log type ioa_detection), the
// processes are left alone.
package ioa

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/tailer"
)

// LogType of the engine's detection lines (decoders/ioa_detection.yaml).
const LogType = "ioa_detection"

const (
	queueSize    = 8192
	maxProcs     = 50000
	maxMarks     = 20000
	procTTL      = 2 * time.Hour // a process not heard of for this long is forgotten
	backlogTTL   = 10 * time.Second
	backlogPer   = 16
	maxBacklog   = 4096
	cooldown     = 15 * time.Minute // one report per rule and program for this long
	maxAncestors = 32
	maxChain     = 8
)

// Options wire the engine to the agent.
type Options struct {
	// Push sends one line of LogType to the server.
	Push func(logType, line string)
	// Mode is the group policy's ioa setting: off or detect ("" is detect).
	Mode func() string
	// Excluded: the group policy's exclusions with the ioa scope.
	Excluded func(image, commandLine string) bool
	// Self is the agent's own process: its children are never reported.
	Self uint32
	// Now is the clock (tests); nil is time.Now.
	Now func() time.Time
	// GOOS picks the rules (tests); "" is runtime.GOOS.
	GOOS string
}

// proc is one process the engine knows.
type proc struct {
	pid         uint32
	ppid        uint32
	image       string
	commandLine string
	user        string
	parentImage string // from the start line, for a parent the engine never saw
	parent      *proc
	started     time.Time
	seen        time.Time
	provisional bool // made from a non-process event; its start line may follow
}

// mark is one rule in progress: its anchor and the steps seen so far.
type mark struct {
	rule     *Rule
	anchor   *proc
	root     *proc // tree steps must come from root or a process under it
	next     int
	key      string // for a keyed next step
	deadline time.Time
	chain    []string
	done     bool
}

type queued struct {
	logType, line string
}

// Engine runs the rules over the lines it is fed.
type Engine struct {
	opt   Options
	rules []*Rule
	in    chan queued
	stop  chan struct{}
	wg    sync.WaitGroup

	dropped  atomic.Uint64
	detected atomic.Uint64

	// state: only the run goroutine (or Feed in tests) touches it
	procs   map[uint32]*proc
	byRoot  map[*proc][]*mark
	byKey   map[string][]*mark
	nmarks  int
	backlog map[uint32][]backlogged
	last    map[string]time.Time // cooldown: rule + program
	sweep   time.Time
}

type backlogged struct {
	ev Event
	at time.Time
}

// New builds an engine with the rules for this OS.
func New(opt Options) *Engine {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.GOOS == "" {
		opt.GOOS = runtime.GOOS
	}
	e := &Engine{opt: opt, in: make(chan queued, queueSize), stop: make(chan struct{}),
		procs: map[uint32]*proc{}, byRoot: map[*proc][]*mark{}, byKey: map[string][]*mark{},
		backlog: map[uint32][]backlogged{}, last: map[string]time.Time{}}
	for _, r := range Rules() {
		if r.OS == "" || r.OS == opt.GOOS {
			e.rules = append(e.rules, r)
		}
	}
	return e
}

// RuleCount is how many rules run on this OS.
func (e *Engine) RuleCount() int { return len(e.rules) }

// Observe takes one buffer entry (tailer.Encode form). It never blocks: when
// the engine falls behind the line is dropped and counted.
func (e *Engine) Observe(entry string) {
	// the log type ends at the first NUL: checked before any allocation,
	// as this runs on every line every sensor pushes
	if i := strings.IndexByte(entry, 0); i < 0 || !logTypes[entry[:i]] {
		return
	}
	logType, _, line := tailer.Decode(entry)
	select {
	case e.in <- queued{logType, line}:
	default:
		e.dropped.Add(1)
	}
}

// Start runs the engine until Stop.
func (e *Engine) Start() {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		report := time.NewTicker(10 * time.Minute)
		defer report.Stop()
		var reported uint64
		for {
			select {
			case <-e.stop:
				return
			case q := <-e.in:
				e.Feed(q.logType, q.line)
			case <-report.C:
				if d := e.dropped.Load(); d != reported {
					slog.Warn("ioa: lines dropped (engine behind the sensors)", "dropped", d-reported)
					reported = d
				}
			}
		}
	}()
}

// Stop ends Start's goroutine.
func (e *Engine) Stop() {
	close(e.stop)
	e.wg.Wait()
}

// Detected is how many chains were reported.
func (e *Engine) Detected() uint64 { return e.detected.Load() }

func (e *Engine) mode() string {
	if e.opt.Mode == nil {
		return "detect"
	}
	switch m := e.opt.Mode(); m {
	case "off":
		return "off"
	default:
		return "detect"
	}
}

// Feed handles one sensor line (synchronously: Start's goroutine, or tests).
func (e *Engine) Feed(logType, line string) {
	if e.mode() == "off" {
		return
	}
	ev, ok := normalize(logType, line)
	if !ok || ev.PID == 0 {
		return
	}
	now := e.opt.Now()
	if now.Sub(e.sweep) > time.Minute {
		e.gc(now)
		e.sweep = now
	}
	if ev.Kind == KindProc {
		p := e.started(ev, now)
		e.handle(ev, p, now, true)
		// lines of this process that came before its start line (Windows
		// joins a process's start for a few seconds; its first connections
		// are sent at once)
		if bl := e.backlog[ev.PID]; len(bl) > 0 {
			delete(e.backlog, ev.PID)
			for _, b := range bl {
				if now.Sub(b.at) <= backlogTTL {
					e.handle(b.ev, p, now, false)
				}
			}
		}
		return
	}
	p := e.procs[ev.PID]
	if p == nil {
		p = &proc{pid: ev.PID, ppid: ev.PPID, image: ev.Image, user: ev.User, started: now, seen: now, provisional: true}
		if pp := e.procs[ev.PPID]; ev.PPID != 0 && pp != nil {
			p.parent = pp
		}
		e.addProc(p)
	} else {
		p.seen = now
	}
	if p.provisional {
		e.keepBacklog(ev, now)
	}
	e.handle(ev, p, now, true)
}

// started records a process start: a new proc, or the provisional one
// earlier lines of the same pid made.
func (e *Engine) started(ev Event, now time.Time) *proc {
	p := e.procs[ev.PID]
	if p != nil && p.provisional && now.Sub(p.started) <= backlogTTL {
		p.provisional = false
	} else {
		p = &proc{pid: ev.PID, started: now}
		e.addProc(p)
	}
	p.ppid, p.image, p.commandLine, p.user, p.parentImage, p.seen = ev.PPID, ev.Image, ev.CommandLine, ev.User, ev.ParentImage, now
	if pp := e.procs[ev.PPID]; ev.PPID != 0 && pp != nil && pp != p {
		p.parent = pp
	} else {
		p.parent = nil
	}
	return p
}

func (e *Engine) addProc(p *proc) {
	if len(e.procs) >= maxProcs {
		e.gc(e.opt.Now())
		if len(e.procs) >= maxProcs {
			for pid := range e.procs { // still full: forget an arbitrary one
				delete(e.procs, pid)
				break
			}
		}
	}
	e.procs[p.pid] = p
}

func (e *Engine) keepBacklog(ev Event, now time.Time) {
	if _, ok := e.backlog[ev.PID]; !ok && len(e.backlog) >= maxBacklog {
		return
	}
	bl := append(e.backlog[ev.PID], backlogged{ev, now})
	if len(bl) > backlogPer {
		bl = bl[len(bl)-backlogPer:]
	}
	e.backlog[ev.PID] = bl
}

// self: the agent or a process it started.
func (e *Engine) self(p *proc) bool {
	if e.opt.Self == 0 {
		return false
	}
	for q, i := p, 0; q != nil && i < maxAncestors; q, i = q.parent, i+1 {
		if q.pid == e.opt.Self || q.ppid == e.opt.Self {
			return true
		}
	}
	return false
}

// handle advances the marks the event continues, then starts the rules it
// anchors (anchor: false when replaying a backlog, whose lines were already
// tried as anchors).
func (e *Engine) handle(ev Event, p *proc, now time.Time, anchor bool) {
	if e.self(p) {
		return
	}
	// tree steps: marks rooted at p or an ancestor of p
	var cont []*mark
	for q, i := p, 0; q != nil && i < maxAncestors; q, i = q.parent, i+1 {
		cont = append(cont, e.byRoot[q]...)
	}
	// keyed steps: a file a step before named (dropped, then run)
	if k := eventKey(ev); k != "" {
		cont = append(cont, e.byKey[baseName(k)]...)
	}
	seen := make(map[*mark]bool, len(cont))
	for _, m := range cont {
		if seen[m] {
			continue // listed under its anchor and under a later root
		}
		seen[m] = true
		if m.done || now.After(m.deadline) || m.next >= len(m.rule.Steps) {
			continue
		}
		st := &m.rule.Steps[m.next]
		if st.Kinds&ev.Kind == 0 {
			continue
		}
		if st.Keyed {
			if !keyMatch(m.key, eventKey(ev)) {
				continue
			}
		} else if !under(p, m.root) {
			continue
		}
		if st.Match != nil && !st.Match(&ev, p) {
			continue
		}
		e.advance(m, st, ev, p, now)
	}
	if !anchor {
		return
	}
	for _, r := range e.rules {
		st := &r.Steps[0]
		if st.Kinds&ev.Kind == 0 || (st.Match != nil && !st.Match(&ev, p)) {
			continue
		}
		if e.anchored(r, p) {
			continue
		}
		if e.nmarks >= maxMarks {
			e.gc(now)
			if e.nmarks >= maxMarks {
				return
			}
		}
		m := &mark{rule: r, anchor: p, root: p, deadline: now.Add(r.Window)}
		e.byRoot[p] = append(e.byRoot[p], m)
		e.nmarks++
		e.advance(m, st, ev, p, now)
	}
}

// anchored: r already runs from p.
func (e *Engine) anchored(r *Rule, p *proc) bool {
	now := e.opt.Now()
	for _, m := range e.byRoot[p] {
		if m.rule == r && m.anchor == p && !m.done && !now.After(m.deadline) {
			return true
		}
	}
	return false
}

func under(p, root *proc) bool {
	for q, i := p, 0; q != nil && i < maxAncestors; q, i = q.parent, i+1 {
		if q == root {
			return true
		}
	}
	return false
}

// advance records step st of m as seen in ev.
func (e *Engine) advance(m *mark, st *Step, ev Event, p *proc, now time.Time) {
	if len(m.chain) < maxChain {
		m.chain = append(m.chain, describe(ev, st.Name))
	}
	m.next++
	if !st.Keyed && st.Narrow && p != m.root { // later steps must come from this process's tree
		e.reroot(m, p)
	}
	if m.next >= len(m.rule.Steps) {
		m.done = true
		e.report(m, ev, p, now)
		return
	}
	if nx := &m.rule.Steps[m.next]; nx.Keyed && st.Capture != nil {
		if k := normKey(st.Capture(&ev)); k != "" {
			m.key = k
			e.byKey[baseName(k)] = append(e.byKey[baseName(k)], m)
		}
	}
}

func (e *Engine) reroot(m *mark, p *proc) {
	// the mark stays listed under its old root too; under() keeps it honest
	m.root = p
	e.byRoot[p] = append(e.byRoot[p], m)
}

// describe is one link of the chain, for the analyst.
func describe(ev Event, step string) string {
	img := baseName(ev.Image)
	switch ev.Kind {
	case KindProc:
		return fmt.Sprintf("%s: %s (pid %d)", step, img, ev.PID)
	case KindNet:
		return fmt.Sprintf("%s: %s -> %s:%d", step, img, ev.DestIP, ev.DestPort)
	case KindFile:
		return fmt.Sprintf("%s: %s wrote %s", step, img, ev.Path)
	case KindAccess, KindThread:
		return fmt.Sprintf("%s: %s %s %s", step, img, ev.Action, baseName(ev.TargetImage))
	case KindPriv:
		return fmt.Sprintf("%s: %s %s(%s)", step, img, ev.Action, ev.IDs)
	}
	return step
}

// report sends one detection, unless excluded or in cooldown.
func (e *Engine) report(m *mark, ev Event, p *proc, now time.Time) {
	a := m.anchor
	for _, q := range []*proc{a, p} {
		if q != nil && e.opt.Excluded != nil && e.opt.Excluded(q.image, q.commandLine) {
			return
		}
	}
	key := m.rule.ID + "\x00" + strings.ToLower(a.image) + "\x00" + strings.ToLower(p.image)
	if t, ok := e.last[key]; ok && now.Sub(t) < cooldown {
		return
	}
	e.last[key] = now
	e.detected.Add(1)
	parent := a.parentImage
	if a.parent != nil {
		parent = a.parent.image
	}
	if e.opt.Push != nil {
		e.opt.Push(LogType, Line(Detection{
			Rule: m.rule, Action: "detected",
			Image: p.image, PID: p.pid, CommandLine: p.commandLine, User: p.user,
			AnchorImage: a.image, AnchorPID: a.pid, AnchorCommandLine: a.commandLine, ParentImage: parent,
			Chain: m.chain,
		}))
	}
}

// gc forgets expired marks, old processes, stale backlogs and cooldowns.
func (e *Engine) gc(now time.Time) {
	live := func(ms []*mark) []*mark {
		out := ms[:0]
		for _, m := range ms {
			if !m.done && !now.After(m.deadline) {
				out = append(out, m)
			}
		}
		return out
	}
	n := 0
	seen := map[*mark]bool{}
	for r, ms := range e.byRoot {
		ms = live(ms)
		if len(ms) == 0 {
			delete(e.byRoot, r)
			continue
		}
		e.byRoot[r] = ms
		for _, m := range ms {
			if !seen[m] {
				seen[m] = true
				n++
			}
		}
	}
	e.nmarks = n
	for k, ms := range e.byKey {
		if ms = live(ms); len(ms) == 0 {
			delete(e.byKey, k)
		} else {
			e.byKey[k] = ms
		}
	}
	for pid, p := range e.procs {
		if now.Sub(p.seen) > procTTL && len(e.byRoot[p]) == 0 {
			delete(e.procs, pid)
		}
	}
	// a parent pointer keeps a forgotten process alive only as long as its
	// children: cut the chains to forgotten ones so memory stays bounded
	for _, p := range e.procs {
		if p.parent != nil && e.procs[p.parent.pid] != p.parent {
			if len(e.byRoot[p.parent]) == 0 {
				p.parent = nil
			}
		}
	}
	for pid, bl := range e.backlog {
		if len(bl) == 0 || now.Sub(bl[len(bl)-1].at) > backlogTTL {
			delete(e.backlog, pid)
		}
	}
	for k, t := range e.last {
		if now.Sub(t) > cooldown {
			delete(e.last, k)
		}
	}
}

// ─── keys: the file a step named, matched by a later step ────────────

// normKey: Windows paths compare case-insensitively.
func normKey(p string) string {
	if len(p) >= 2 && (p[1] == ':' || strings.HasPrefix(p, `\\`)) {
		return strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	}
	return p
}

// eventKey is the file an event is about: the program a process runs, or
// the file written.
func eventKey(ev Event) string {
	switch ev.Kind {
	case KindProc:
		return normKey(ev.Image)
	case KindFile:
		return normKey(ev.Path)
	}
	return ""
}

// keyMatch: got names the captured file. A Linux exec may name it relative
// to the working directory (./x, bin/x): matched by its tail.
func keyMatch(want, got string) bool {
	if want == "" || got == "" {
		return false
	}
	if want == got {
		return true
	}
	if strings.HasPrefix(got, "/") || (len(got) >= 2 && got[1] == ':') {
		return false
	}
	return strings.HasSuffix(want, "/"+strings.TrimPrefix(got, "./"))
}
