//go:build windows

package winsensor

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	dropped  atomic.Uint64 // events lost because the agent was behind
}

type kind int

const (
	kernelProcess kind = iota
	providerProcess
	networkEvent
	dnsEvent
)

type source struct {
	kind kind
	ev   *etw.Event
}

// LogTypeStatus reports the sensor's own losses (events dropped because the
// agent fell behind), so they are visible on the server.
const LogTypeStatus = "windows_etw_status"

// Start begins process, network and DNS telemetry: a private kernel logger
// session (command lines, users), Microsoft-Windows-Kernel-Process (image
// paths, integrity levels), Kernel-Network TCP connect/accept and DNS-Client
// query completions, the last three filtered to those events in the kernel.
func Start(buf *buffer.Buffer) (*Sensor, error) {
	s := &Sensor{events: make(chan source, 8192), stop: make(chan struct{}), done: make(chan struct{})}
	push := func(k kind) func(*etw.Event) {
		return func(ev *etw.Event) {
			select {
			case s.events <- source{k, ev}:
			default: // the agent is behind: count and drop rather than stall the ETW consumer
				s.dropped.Add(1)
			}
		}
	}
	configs := []struct {
		cfg etw.Config
		k   kind
	}{
		{etw.Config{Name: "SIEMAgent-Kernel", KernelFlags: etw.KernelProcess}, kernelProcess},
		{etw.Config{Name: "SIEMAgent-Process", Providers: []etw.Provider{{GUID: kernelProcessProvider,
			Keywords: 0x10, EventIDs: []uint16{1}}}}, providerProcess}, // WINEVENT_KEYWORD_PROCESS, ProcessStart
		{etw.Config{Name: "SIEMAgent-Network", Providers: []etw.Provider{{GUID: kernelNetworkProvider,
			Keywords: 0x10 | 0x20, EventIDs: networkEventIDs}}}, networkEvent}, // IPv4 | IPv6
		{etw.Config{Name: "SIEMAgent-DNS", Providers: []etw.Provider{{GUID: dnsClientProvider,
			EventIDs: dnsEventIDs}}}, dnsEvent},
	}
	for _, c := range configs {
		ses, err := etw.Start(c.cfg, push(c.k))
		if err != nil {
			for _, started := range s.sessions {
				started.Close()
			}
			return nil, err
		}
		s.sessions = append(s.sessions, ses)
	}

	devices := newDeviceMap()
	j := newProcessJoiner(processImagePath, devices.dosPath)
	go s.run(j, buf)
	return s, nil
}

func (s *Sensor) run(j *processJoiner, buf *buffer.Buffer) {
	defer close(s.done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	report := time.NewTicker(time.Minute)
	defer report.Stop()
	var reported uint64
	emit := func(logType string, lines ...string) {
		for _, l := range lines {
			if l != "" {
				buf.Push(tailer.Encode(logType, l))
			}
		}
	}
	for {
		select {
		case <-s.stop:
			emit(LogTypeProcess, j.flush(time.Now().Add(joinWindow))...)
			return
		case src := <-s.events:
			now := time.Now()
			switch src.kind {
			case kernelProcess:
				emit(LogTypeProcess, j.kernel(src.ev, now)...)
			case providerProcess:
				emit(LogTypeProcess, j.provider(src.ev, now)...)
			case networkEvent:
				emit(LogTypeNetwork, j.network(src.ev))
			case dnsEvent:
				emit(LogTypeDNS, j.dns(src.ev))
			}
		case now := <-tick.C:
			emit(LogTypeProcess, j.flush(now)...)
		case <-report.C:
			if d := s.dropped.Load(); d != reported {
				slog.Warn("etw sensor dropped events: the agent fell behind", "dropped", d-reported)
				emit(LogTypeStatus, line(255, [][2]string{{"Channel", "ETW"}, {"Provider", "SIEMAgent"},
					{"Dropped", strconv.FormatUint(d-reported, 10)}, {"DroppedTotal", strconv.FormatUint(d, 10)}}))
				reported = d
			}
		}
	}
}

// Dropped is the number of events lost because the agent fell behind.
func (s *Sensor) Dropped() uint64 { return s.dropped.Load() }

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
