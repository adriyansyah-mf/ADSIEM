//go:build windows

package winsensor

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/etw"
	"github.com/siem-platform/agent/internal/tailer"
)

// Sensor runs the ETW sessions and pushes telemetry lines into the buffer.
type Sensor struct {
	sessions []*etw.Session
	events   chan source
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

type source struct {
	kernel bool
	ev     *etw.Event
}

// Start begins process telemetry: a private kernel logger session (command
// lines and users) and Microsoft-Windows-Kernel-Process (image paths and
// integrity levels), joined per process.
func Start(buf *buffer.Buffer) (*Sensor, error) {
	s := &Sensor{events: make(chan source, 4096), stop: make(chan struct{}), done: make(chan struct{})}
	push := func(kernel bool) func(*etw.Event) {
		return func(ev *etw.Event) {
			select {
			case s.events <- source{kernel, ev}:
			default: // the agent is behind: drop rather than stall the ETW consumer
			}
		}
	}
	kernel, err := etw.Start(etw.Config{Name: "SIEMAgent-Kernel", KernelFlags: etw.KernelProcess}, push(true))
	if err != nil {
		return nil, err
	}
	s.sessions = append(s.sessions, kernel)
	prov, err := etw.Start(etw.Config{Name: "SIEMAgent-Process",
		Providers: []etw.Provider{{GUID: kernelProcessProvider, Keywords: 0x10}}}, push(false)) // WINEVENT_KEYWORD_PROCESS
	if err != nil {
		kernel.Close()
		return nil, err
	}
	s.sessions = append(s.sessions, prov)

	devices := newDeviceMap()
	j := newProcessJoiner(processImagePath, devices.dosPath)
	go s.run(j, buf)
	return s, nil
}

func (s *Sensor) run(j *processJoiner, buf *buffer.Buffer) {
	defer close(s.done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	emit := func(lines []string) {
		for _, l := range lines {
			buf.Push(tailer.Encode(LogTypeProcess, l))
		}
	}
	for {
		select {
		case <-s.stop:
			emit(j.flush(time.Now().Add(joinWindow)))
			return
		case src := <-s.events:
			if src.kernel {
				emit(j.kernel(src.ev, time.Now()))
			} else {
				emit(j.provider(src.ev, time.Now()))
			}
		case now := <-tick.C:
			emit(j.flush(now))
		}
	}
}

// Stop ends the sessions and flushes what is pending.
func (s *Sensor) Stop() {
	s.once.Do(func() {
		for _, ses := range s.sessions {
			ses.Close()
		}
		close(s.stop)
		<-s.done
	})
}

// processImagePath is QueryFullProcessImageName for a running process.
func processImagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// deviceMap turns NT device paths into drive-letter paths.
type deviceMap struct {
	mu       sync.Mutex
	prefixes map[string]string // \Device\HarddiskVolume3 -> C:
	loaded   time.Time
}

func newDeviceMap() *deviceMap { return &deviceMap{} }

func (d *deviceMap) dosPath(p string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if d.prefixes == nil || (attempt == 1 && time.Since(d.loaded) > time.Minute) {
			d.load()
		}
		for device, drive := range d.prefixes {
			if strings.HasPrefix(strings.ToLower(p), strings.ToLower(device)+`\`) {
				return drive + p[len(device):]
			}
		}
	}
	return p
}

func (d *deviceMap) load() {
	d.prefixes, d.loaded = map[string]string{}, time.Now()
	buf := make([]uint16, 1024)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		name, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		if n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf))); err == nil && n > 0 {
			d.prefixes[windows.UTF16ToString(buf)] = drive
		}
	}
	slog.Debug("etw sensor: device map", "drives", len(d.prefixes))
}
