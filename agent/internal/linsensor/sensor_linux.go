//go:build linux

package linsensor

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
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
	mu      sync.Mutex // guards proc between the reader and the ticker
	stop    chan struct{}
	stopped sync.WaitGroup
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
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			s.proc.tick()
			s.mu.Unlock()
			if report++; report%6 == 0 {
				if d := s.drops(); d > lastDrops {
					slog.Warn("linsensor: ring buffer full, events lost", "lost", d-lastDrops)
					lastDrops = d
				}
			}
		}
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
