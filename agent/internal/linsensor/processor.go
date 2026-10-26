package linsensor

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Event groups that config can switch off (linsensor.disabled).
const (
	GroupFile      = "file"
	GroupModule    = "module"
	GroupPtrace    = "ptrace"
	GroupPrivilege = "privilege"
	GroupMemfd     = "memfd"
	GroupExit      = "exit"
)

const (
	// fileBudget is how many file events one process may ship per
	// window; the rest are counted into one summary line.
	fileBudget   = 30
	fileWindow   = time.Minute
	ptraceDedupe = time.Minute
	memfdDedupe  = 10 * time.Minute
	maxTracked   = 20000
)

// procFS resolves what the kernel record does not carry.
type procFS interface {
	Exe(tgid uint32) string          // executable path, "" if gone
	Cwd(pid, tgid uint32) string     // working directory
	FD(tgid uint32, fd int32) string // path an open fd refers to
}

// skipPrefixes are pseudo and runtime file systems: writes there are
// not file activity anyone hunts for and would drown the rest.
var skipPrefixes = []string{"/proc/", "/sys/", "/dev/", "/run/", "/var/run/"}

func skipPath(p string) bool {
	if strings.HasPrefix(p, "/dev/shm/") {
		return false
	}
	for _, s := range skipPrefixes {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

type fileWindowState struct {
	start                            time.Time
	sent                             int
	writes, renames, deletes, others int
	sample                           string
	image, comm                      string
	ppid, uid                        uint32
}

type processor struct {
	push     func(logType, line string)
	onFile   func(FileEvent)
	disabled map[string]bool
	proc     procFS
	now      func() time.Time

	images map[uint32]string
	files  map[uint32]*fileWindowState
	seen   map[string]time.Time
}

func newProcessor(push func(string, string), onFile func(FileEvent), disabled map[string]bool, proc procFS) *processor {
	return &processor{
		push: push, onFile: onFile, disabled: disabled, proc: proc, now: time.Now,
		images: map[uint32]string{}, files: map[uint32]*fileWindowState{}, seen: map[string]time.Time{},
	}
}

// setImage records the executable the kernel reported at exec.
func (p *processor) setImage(tgid uint32, path string) {
	if path == "" {
		delete(p.images, tgid)
		return
	}
	if len(p.images) >= maxTracked {
		p.images = map[uint32]string{}
	}
	p.images[tgid] = path
}

func (p *processor) image(tgid uint32, comm string) string {
	if img, ok := p.images[tgid]; ok {
		return img
	}
	img := p.proc.Exe(tgid)
	if img == "" {
		return comm
	}
	if len(p.images) >= maxTracked {
		p.images = map[uint32]string{}
	}
	p.images[tgid] = img
	return img
}

// resolve makes path absolute: dir comes from the kernel (always right,
// even for a process that has exited); /proc is the fallback.
func (p *processor) resolve(path, dir string, dfd int32, pid, tgid uint32) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	var base string
	switch {
	case dir != "":
		base = dir
	case dfd == atFDCWD:
		base = p.proc.Cwd(pid, tgid)
	default:
		base = p.proc.FD(tgid, dfd)
	}
	if base == "" {
		return path
	}
	return filepath.Join(base, path)
}

// dedupe reports whether key was seen within d, and records it.
func (p *processor) dedupe(key string, d time.Duration) bool {
	now := p.now()
	if t, ok := p.seen[key]; ok && now.Sub(t) < d {
		return true
	}
	if len(p.seen) >= maxTracked {
		p.seen = map[string]time.Time{}
	}
	p.seen[key] = now
	return false
}

func (p *processor) handle(ev rawEvent) {
	switch ev.kind {
	case kindOpen, kindRename, kindUnlink:
		if !p.disabled[GroupFile] {
			p.handleFile(ev)
		}
	case kindModuleInit, kindModuleFinit, kindModuleDelete:
		if !p.disabled[GroupModule] {
			p.push(LogModule, moduleLine(ev, p.image(ev.tgid, ev.comm)))
		}
	case kindPtrace:
		if p.disabled[GroupPtrace] || p.dedupe(fmt.Sprintf("ptrace|%d|%d|%d", ev.tgid, ev.arg1, ev.arg0), ptraceDedupe) {
			return
		}
		p.push(LogPtrace, ptraceLine(ev, p.image(ev.tgid, ev.comm), p.proc.Exe(uint32(ev.arg1))))
	case kindSetID, kindCapset:
		if !p.disabled[GroupPrivilege] {
			p.push(LogPrivilege, privilegeLine(ev, p.image(ev.tgid, ev.comm), p.image(ev.ppid, "")))
		}
	case kindMemfd:
		img := p.image(ev.tgid, ev.comm)
		if p.disabled[GroupMemfd] || p.dedupe("memfd|"+img+"|"+ev.path, memfdDedupe) {
			return
		}
		p.push(LogMemfd, memfdLine(ev, img))
	case kindExec:
		p.setImage(ev.tgid, ev.path)
	case kindFilelessExec:
		p.setImage(ev.tgid, ev.path)
		// Always reported: running code that has no file on disk is the
		// point of this sensor.
		p.push(LogFileless, filelessLine(ev, p.image(ev.ppid, "")))
	case kindExit:
		if !p.disabled[GroupExit] {
			p.push(LogExit, exitLine(ev, p.image(ev.tgid, ev.comm)))
		}
		delete(p.images, ev.tgid)
		if w := p.files[ev.tgid]; w != nil {
			p.flushFiles(ev.tgid, w)
		}
	}
}

func (p *processor) handleFile(ev rawEvent) {
	fe := FileEvent{
		Time: p.now(), PID: ev.tgid, PPID: ev.ppid, UID: ev.uid, Comm: ev.comm,
		Path: p.resolve(ev.path, ev.dir, ev.dfd, ev.pid, ev.tgid),
	}
	switch ev.kind {
	case kindOpen:
		fe.Action = "write"
		if ev.arg0&oCreat != 0 {
			fe.Action = "create"
		}
	case kindRename:
		fe.Action = "rename"
		fe.From = fe.Path
		fe.Path = p.resolve(ev.path2, ev.dir2, ev.dfd2, ev.pid, ev.tgid)
	case kindUnlink:
		fe.Action = "delete"
		fe.Dir = ev.arg0&atRemovDir != 0
	}
	if skipPath(fe.Path) && (fe.From == "" || skipPath(fe.From)) {
		return
	}
	fe.Image = p.image(ev.tgid, ev.comm)
	if p.onFile != nil {
		p.onFile(fe)
	}

	w := p.files[ev.tgid]
	if w == nil || p.now().Sub(w.start) >= fileWindow {
		if w != nil {
			p.flushFiles(ev.tgid, w)
		}
		if len(p.files) >= maxTracked {
			p.files = map[uint32]*fileWindowState{}
		}
		w = &fileWindowState{start: p.now(), image: fe.Image, comm: fe.Comm, ppid: fe.PPID, uid: fe.UID}
		p.files[ev.tgid] = w
	}
	if p.dedupe(fmt.Sprintf("file|%d|%s|%s", ev.tgid, fe.Action, fe.Path), fileWindow) {
		return
	}
	if w.sent < fileBudget {
		w.sent++
		p.push(LogFile, fe.line())
		return
	}
	switch fe.Action {
	case "create", "write":
		w.writes++
	case "rename":
		w.renames++
	case "delete":
		w.deletes++
	}
	if w.sample == "" {
		w.sample = fe.Path
	}
}

// flushFiles emits the summary of a process's file events over budget.
func (p *processor) flushFiles(tgid uint32, w *fileWindowState) {
	delete(p.files, tgid)
	if w.writes+w.renames+w.deletes == 0 {
		return
	}
	p.push(LogFile, fmt.Sprintf(`action=summary Writes=%d Renames=%d Deletes=%d TargetFilename=%s Image=%s Comm=%s PID=%d PPID=%d User=%d`,
		w.writes, w.renames, w.deletes, kv(w.sample), kv(w.image), kv(w.comm), tgid, w.ppid, w.uid))
}

// tick flushes file windows that have ended; call it periodically.
func (p *processor) tick() {
	now := p.now()
	for tgid, w := range p.files {
		if now.Sub(w.start) >= fileWindow {
			p.flushFiles(tgid, w)
		}
	}
	for k, t := range p.seen {
		if now.Sub(t) >= memfdDedupe {
			delete(p.seen, k)
		}
	}
}
