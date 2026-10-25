// Package winsensor turns ETW events into the agent's Windows telemetry
// lines: process creation, network connections and DNS queries, without
// Sysmon. Lines use Sysmon's field names (Image, CommandLine, ParentImage,
// User, ...) so the SigmaHQ windows rules written for Sysmon apply; their
// log types (windows_etw_*) keep the source visible.
package winsensor

import (
	"strconv"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/etw"
	"github.com/siem-platform/agent/internal/winevent"
)

// LogTypeProcess is process creation (Sigma windows / process_creation).
const LogTypeProcess = "windows_etw_process"

const (
	// joinWindow bounds the wait for the second half of a process start: the
	// kernel logger has the command line and user, Microsoft-Windows-Kernel-
	// Process the full image path and integrity level.
	joinWindow = 1500 * time.Millisecond
	maxKnown   = 8192 // processes remembered for ParentImage / ParentCommandLine
	maxPending = 4096
)

// Microsoft-Windows-Kernel-Process event 1 (ProcessStart).
const kernelProcessProvider = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

// Kernel logger process events: MSNT_SystemTrace, opcode 1 start, 2 end,
// 3 the processes already running when the session started.
const (
	opcodeStart   = 1
	opcodeEnd     = 2
	opcodeDCStart = 3
)

type process struct {
	pid, ppid            uint32
	image, commandLine   string
	user, integrityLevel string
	started              time.Time
	haveKernel, haveProv bool
}

// processJoiner merges the two halves of each process start and remembers
// processes for their children's Parent* fields. Not safe for concurrent use.
type processJoiner struct {
	// fullImage resolves a running process's image path (QueryFullProcessImageName).
	fullImage func(pid uint32) string
	// dosPath turns \Device\HarddiskVolumeN\... into C:\...
	dosPath func(string) string

	pending map[uint32]*process
	known   map[uint32]*process
	order   []uint32 // known, oldest first, for eviction
}

func newProcessJoiner(fullImage func(uint32) string, dosPath func(string) string) *processJoiner {
	return &processJoiner{fullImage: fullImage, dosPath: dosPath,
		pending: map[uint32]*process{}, known: map[uint32]*process{}}
}

// kernel takes a kernel logger process event. It returns a line when this
// completes a start.
func (j *processJoiner) kernel(ev *etw.Event, now time.Time) []string {
	pid, ok := number(ev, "ProcessId")
	if !ok {
		return nil
	}
	switch ev.Opcode {
	case opcodeDCStart: // already running: only remembered
		ppid, _ := number(ev, "ParentId")
		cmd, _ := ev.Get("CommandLine")
		image, _ := ev.Get("ImageFileName")
		j.remember(&process{pid: pid, ppid: ppid, image: image, commandLine: cmd})
		return nil
	case opcodeEnd:
		return nil // kept for children that start right after; evicted by age
	case opcodeStart:
		p := j.entry(pid, now)
		p.ppid, _ = number(ev, "ParentId")
		p.commandLine, _ = ev.Get("CommandLine")
		p.user = account(ev)
		if p.image == "" {
			p.image, _ = ev.Get("ImageFileName") // a name only: the provider half has the path
		}
		p.haveKernel = true
		return j.complete(pid)
	}
	return nil
}

// provider takes a Microsoft-Windows-Kernel-Process event.
func (j *processJoiner) provider(ev *etw.Event, now time.Time) []string {
	if ev.ID != 1 {
		return nil
	}
	pid, ok := number(ev, "ProcessID")
	if !ok {
		return nil
	}
	p := j.entry(pid, now)
	if image, _ := ev.Get("ImageName"); image != "" {
		p.image = j.dosPath(image)
	}
	if p.ppid == 0 {
		p.ppid, _ = number(ev, "ParentProcessID")
	}
	if label, ok := ev.Get("MandatoryLabel"); ok {
		p.integrityLevel = integrityLevel(label)
	}
	p.haveProv = true
	return j.complete(pid)
}

// flush emits the starts whose other half did not arrive in time.
func (j *processJoiner) flush(now time.Time) []string {
	var lines []string
	for pid, p := range j.pending {
		if now.Sub(p.started) >= joinWindow {
			lines = append(lines, j.emit(pid)...)
		}
	}
	return lines
}

func (j *processJoiner) entry(pid uint32, now time.Time) *process {
	if p, ok := j.pending[pid]; ok {
		return p
	}
	if len(j.pending) >= maxPending { // a burst of half events: emit the oldest rather than grow
		var oldest uint32
		for id, p := range j.pending {
			if o, ok := j.pending[oldest]; !ok || p.started.Before(o.started) {
				oldest = id
			}
		}
		j.emit(oldest)
	}
	p := &process{pid: pid, started: now}
	j.pending[pid] = p
	return p
}

func (j *processJoiner) complete(pid uint32) []string {
	if p := j.pending[pid]; p != nil && p.haveKernel && p.haveProv {
		return j.emit(pid)
	}
	return nil
}

func (j *processJoiner) emit(pid uint32) []string {
	p := j.pending[pid]
	delete(j.pending, pid)
	if p == nil || !p.haveKernel && !p.haveProv {
		return nil
	}
	if !strings.ContainsRune(p.image, '\\') { // only a name: ask the process while it lives
		if full := j.fullImage(pid); full != "" {
			p.image = full
		}
	}
	j.remember(p)
	parent := j.known[p.ppid]
	if parent != nil && !strings.ContainsRune(parent.image, '\\') {
		if full := j.fullImage(p.ppid); full != "" {
			parent.image = full
		}
	}
	return []string{processLine(p, parent)}
}

func (j *processJoiner) remember(p *process) {
	if _, ok := j.known[p.pid]; !ok {
		j.order = append(j.order, p.pid)
	}
	j.known[p.pid] = p
	for len(j.order) > maxKnown {
		old := j.order[0]
		j.order = j.order[1:]
		if q := j.known[old]; q != nil && q.pid == old {
			delete(j.known, old)
		}
	}
}

// processLine is a Sysmon event 1 lookalike.
func processLine(p, parent *process) string {
	fields := [][2]string{
		{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-Process"},
		{"ProcessId", strconv.FormatUint(uint64(p.pid), 10)},
		{"Image", p.image}, {"CommandLine", p.commandLine},
		{"User", p.user}, {"IntegrityLevel", p.integrityLevel},
		{"ParentProcessId", strconv.FormatUint(uint64(p.ppid), 10)},
	}
	if parent != nil {
		fields = append(fields, [2]string{"ParentImage", parent.image}, [2]string{"ParentCommandLine", parent.commandLine})
	}
	return line(1, fields)
}

// line formats EventID=<id> Key="value" ... skipping empty values.
func line(id int, fields [][2]string) string {
	var b strings.Builder
	b.WriteString("EventID=" + strconv.Itoa(id))
	for _, f := range fields {
		if f[1] != "" {
			b.WriteString(" " + f[0] + "=" + winevent.Quote(f[1]))
		}
	}
	return b.String()
}

// number reads an integer property (MOF ids are formatted in hex).
func number(ev *etw.Event, name string) (uint32, bool) {
	v, ok := ev.Get(name)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 0, 32)
	return uint32(n), err == nil
}

// account is the kernel's UserSID as DOMAIN\user (TDH formats it \\DOMAIN\user).
func account(ev *etw.Event) string {
	v, _ := ev.Get("UserSID")
	return strings.TrimPrefix(v, `\\`)
}

// integrityLevel maps a mandatory label SID to Sysmon's IntegrityLevel names.
func integrityLevel(sid string) string {
	switch sid {
	case "S-1-16-0":
		return "Untrusted"
	case "S-1-16-4096":
		return "Low"
	case "S-1-16-8192":
		return "Medium"
	case "S-1-16-8448":
		return "MediumPlus"
	case "S-1-16-12288":
		return "High"
	case "S-1-16-16384":
		return "System"
	case "S-1-16-20480":
		return "Protected"
	}
	return ""
}
