//go:build linux

package linsensor

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/siem-platform/agent/internal/mountns"
)

//go:embed bpf/linsensor.bpf.o
var sensorObj []byte

// x86-only syscalls (arm64 has only the *at forms): their tracepoints do
// not exist there.
var optionalTracepoints = map[string]bool{
	"sys_enter_open": true, "sys_exit_open": true, "sys_enter_creat": true, "sys_exit_creat": true,
	"sys_enter_rename": true, "sys_exit_rename": true, "sys_enter_unlink": true, "sys_exit_unlink": true,
	"sys_enter_rmdir": true, "sys_exit_rmdir": true,
}

// Options configure the sensor.
type Options struct {
	// Push receives one log line per reported event.
	Push func(logType, line string)
	// OnFile, if set, sees every file event before rate limiting (the
	// anti-ransomware heuristics run on it).
	OnFile func(FileEvent)
	// Disabled event groups (GroupFile, GroupModule, ...).
	Disabled []string
}

type Sensor struct {
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	proc    *processor
	mu      sync.Mutex // guards proc and health between the reader and the ticker
	stop    chan struct{}
	stopped sync.WaitGroup

	self   uint32         // the agent's tgid, as announced to the kernel
	health *healthChecker // nil when file events are disabled (no canary to see)
}

// Start loads and attaches the sensor. Like procexec it needs CAP_BPF (or
// CAP_SYS_ADMIN), tracefs and a BTF kernel; callers treat an error as
// "running without it".
func Start(opts Options) (*Sensor, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(sensorObj))
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load collection into kernel: %w", err)
	}
	s := &Sensor{coll: coll, stop: make(chan struct{})}
	var skipped []string
	for name, ps := range spec.Programs {
		if raw, ok := strings.CutPrefix(ps.SectionName, "raw_tracepoint/"); ok {
			l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: raw, Program: coll.Programs[name]})
			if err != nil {
				s.close()
				return nil, fmt.Errorf("attach raw tracepoint %s: %w", raw, err)
			}
			s.links = append(s.links, l)
			continue
		}
		group, tp, ok := strings.Cut(strings.TrimPrefix(ps.SectionName, "tracepoint/"), "/")
		if !ok {
			continue
		}
		l, err := link.Tracepoint(group, tp, coll.Programs[name], nil)
		if err != nil {
			if optionalTracepoints[tp] {
				skipped = append(skipped, tp)
				continue
			}
			s.close()
			return nil, fmt.Errorf("attach %s/%s: %w", group, tp, err)
		}
		s.links = append(s.links, l)
	}
	if s.reader, err = ringbuf.NewReader(coll.Maps["sensor_events"]); err != nil {
		s.close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	self, err := s.announceSelf()
	if err != nil {
		s.close()
		return nil, err
	}
	disabled := map[string]bool{}
	for _, g := range opts.Disabled {
		disabled[g] = true
	}
	s.proc = newProcessor(opts.Push, opts.OnFile, disabled, linuxProc{})
	s.proc.hostPath = func(tgid uint32, p string) string { return mountns.HostPath(int(tgid), p) }
	s.self = self
	if !disabled[GroupFile] {
		s.health = newHealthChecker(fmt.Sprintf("/var/tmp/.siem-sensor-canary-%d", os.Getpid()))
		s.proc.canary = s.health.claim
	}
	s.stopped.Add(2)
	go s.read()
	go s.ticker()
	slog.Info("linsensor: attached", "tracepoints", len(s.links), "skipped", skipped,
		"disabled", opts.Disabled, "self_tgid", self)
	return s, nil
}

// selfMagic matches SELF_MAGIC in bpf/linsensor.bpf.c.
const selfMagic = 0x4c53454e

// announceSelf makes the kernel side learn the agent's tgid as the kernel
// numbers it (os.Getpid is the container's view). Without it the sensor
// would report the agent's own journal writes, which make more writes.
func (s *Sensor) announceSelf() (uint32, error) {
	unix.Prctl(selfMagic, 0, 0, 0, 0) // EINVAL; the tracepoint saw it
	var tgid uint32
	if err := s.coll.Maps["self"].Lookup(uint32(0), &tgid); err != nil || tgid == 0 {
		return 0, fmt.Errorf("linsensor: could not identify the agent's own process (self tgid %d): %v", tgid, err)
	}
	return tgid, nil
}

func (s *Sensor) close() {
	for _, l := range s.links {
		l.Close()
	}
	if s.reader != nil {
		s.reader.Close()
	}
	s.coll.Close()
}

func (s *Sensor) Stop() {
	close(s.stop)
	s.reader.Close()
	s.stopped.Wait()
	s.close()
}

func (s *Sensor) read() {
	defer s.stopped.Done()
	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("linsensor: ringbuf read error", "err", err)
			continue
		}
		ev, ok := decodeRaw(rec.RawSample)
		if !ok {
			continue
		}
		s.mu.Lock()
		s.proc.handle(ev)
		s.mu.Unlock()
	}
}

func (s *Sensor) ticker() {
	defer s.stopped.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	var lastDrops uint64
	report := 0
	selfEvery := int(selfCheckEvery / (10 * time.Second))
	canaryTicks := int(canaryEvery / (10 * time.Second))
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			s.proc.tick()
			var verdict string
			if s.health != nil {
				verdict = s.health.verdict()
			}
			s.mu.Unlock()
			if verdict != "" {
				s.proc.push(LogHealth, verdict)
				slog.Warn("linsensor: health", "check", verdict)
			}
			if report%selfEvery == selfEvery-1 {
				s.checkSelf()
			}
			if s.health != nil && report%canaryTicks == 2 { // first one 30 s after start
				s.runCanary()
			}
			if report++; report%6 == 0 {
				if d := s.drops(); d > lastDrops {
					slog.Warn("linsensor: ring buffer full, events lost", "lost", d-lastDrops)
					lastDrops = d
				}
			}
		}
	}
}

// checkSelf re-reads the self map: another tgid there hides that process.
// It is restored and reported.
func (s *Sensor) checkSelf() {
	var tgid uint32
	m := s.coll.Maps["self"]
	if err := m.Lookup(uint32(0), &tgid); err == nil && tgid == s.self {
		return
	}
	err := m.Update(uint32(0), s.self, ebpf.UpdateAny)
	s.proc.push(LogHealth, selfLine(s.self, tgid, err == nil, err))
	slog.Warn("linsensor: self map overwritten", "expected", s.self, "found", tgid, "restore_err", err)
}

// runCanary creates and removes the canary file from a child process (the
// agent's own events are skipped in the kernel), for verdict to judge.
func (s *Sensor) runCanary() {
	s.mu.Lock()
	s.health.start()
	path := s.health.canaryPath
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "/bin/sh", "-c", `: > "$1" && rm -f "$1"`, "sh", path).Run()
	if err != nil { // no shell (a minimal container) or no /var/tmp: nothing to judge
		s.mu.Lock()
		s.health.abort()
		s.mu.Unlock()
		slog.Debug("linsensor: canary not run", "err", err)
	}
}

func (s *Sensor) drops() uint64 {
	var perCPU []uint64
	if err := s.coll.Maps["drops"].Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}
	var n uint64
	for _, v := range perCPU {
		n += v
	}
	return n
}

// stats sums the BPF enter/exit pairing counters (ST_* in linsensor.bpf.c).
func (s *Sensor) stats() map[string]uint64 {
	names := []string{"stash", "take_ok", "missing", "kind_mismatch", "failed", "stash_err"}
	out := map[string]uint64{}
	m := s.coll.Maps["stats"]
	if m == nil {
		return out
	}
	for i, name := range names {
		var perCPU []uint64
		if err := m.Lookup(uint32(i), &perCPU); err != nil {
			continue
		}
		for _, v := range perCPU {
			out[name] += v
		}
	}
	return out
}

type linuxProc struct{}

func (linuxProc) Exe(tgid uint32) string {
	p, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", tgid))
	return p
}

func (linuxProc) Cwd(pid, tgid uint32) string {
	if p, err := os.Readlink(fmt.Sprintf("/proc/%d/task/%d/cwd", tgid, pid)); err == nil {
		return p
	}
	p, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", tgid))
	return p
}

func (linuxProc) FD(tgid uint32, fd int32) string {
	p, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tgid, fd))
	return p
}
