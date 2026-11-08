//go:build windows

package winsensor

import (
	"log/slog"
	"path/filepath"
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
	q        *eventQueue // SIEM events, and the guard's writes apart
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	onScript func(AMSIScript)
}

// LogTypeStatus reports the sensor's own losses (SIEM events, and the
// guard's file writes apart, dropped because the agent fell behind), so they
// are visible on the server.
const LogTypeStatus = "windows_etw_status"

// Start begins process, network, DNS, file and image telemetry: a private
// kernel logger session (command lines, users), Microsoft-Windows-Kernel-
// Process (image paths, integrity levels), Kernel-Network TCP connect/accept,
// DNS-Client query completions, Kernel-File creates, renames and deletes and
// Kernel-Process image loads, each filtered to those events in the kernel.
// disabled names event groups (GroupFile, GroupImage) not to start.
func Start(buf *buffer.Buffer, disabled ...string) (*Sensor, error) {
	return StartWith(buf, Options{Disabled: disabled})
}

// StartWith is Start with Options (OnFile for the anti-ransomware guard).
func StartWith(buf *buffer.Buffer, opts Options) (*Sensor, error) {
	off := map[string]bool{}
	for _, g := range opts.Disabled {
		off[g] = true
	}
	s := &Sensor{q: newEventQueue(eventQueueSize, writeQueueSize), stop: make(chan struct{}), done: make(chan struct{})}
	push := s.q.push
	// Remote threads come in the process session: one session keeps a new
	// process's start ahead of its first thread, which its parent creates.
	procKeywords, procEvents := uint64(0x10), []uint16{1} // WINEVENT_KEYWORD_PROCESS, ProcessStart
	if !off[GroupAccess] && !off[GroupThread] {
		procKeywords, procEvents = procKeywords|threadKeyword, append(procEvents, threadStartEvent)
	}
	configs := []struct {
		cfg etw.Config
		k   kind
	}{
		{etw.Config{Name: "SIEMAgent-Kernel", KernelFlags: etw.KernelProcess}, kernelProcess},
		{etw.Config{Name: "SIEMAgent-Process", Providers: []etw.Provider{{GUID: kernelProcessProvider,
			Keywords: procKeywords, EventIDs: procEvents}}}, providerProcess},
		{etw.Config{Name: "SIEMAgent-Network", Providers: []etw.Provider{{GUID: kernelNetworkProvider,
			Keywords: 0x10 | 0x20, EventIDs: networkEventIDs}}}, networkEvent}, // IPv4 | IPv6
		{etw.Config{Name: "SIEMAgent-DNS", Providers: []etw.Provider{{GUID: dnsClientProvider,
			EventIDs: dnsEventIDs}}}, dnsEvent},
	}
	if !off[GroupFile] {
		configs = append(configs, struct {
			cfg etw.Config
			k   kind
		}{etw.Config{Name: "SIEMAgent-File", Providers: []etw.Provider{{GUID: kernelFileProvider,
			Keywords: kernelFileKeywords, EventIDs: fileEventIDs}}}, fileEvent})
	}
	if !off[GroupImage] {
		configs = append(configs, struct {
			cfg etw.Config
			k   kind
		}{etw.Config{Name: "SIEMAgent-Image", Providers: []etw.Provider{{GUID: kernelProcessProvider,
			Keywords: imageKeyword, EventIDs: []uint16{imageLoadEvent}}}}, imageEvent})
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
	// File writes for the ransomware guard: a session of their own (their own
	// ETW buffers, consumer and queue), so their volume never costs the SIEM
	// sessions an event. Optional: without it the guard has canary checks
	// and the create/rename/delete heuristics.
	if opts.OnFile != nil && !off[GroupFile] {
		p, fast := writeProvider()
		ses, err := etw.Start(etw.Config{Name: "SIEMAgent-FileWrite", Providers: []etw.Provider{p}, Fast: fast},
			push(writeEvent))
		if err != nil {
			slog.Warn("etw: file writes for the ransomware guard unavailable", "err", err)
		} else {
			s.sessions = append(s.sessions, ses)
		}
	}
	// AMSI content for the script scanner: optional too.
	if opts.OnScript != nil && !off[GroupAMSI] {
		ses, err := etw.Start(etw.Config{Name: "SIEMAgent-AMSI", Providers: []etw.Provider{{GUID: amsiProvider,
			EventIDs: []uint16{amsiScanEvent}}}}, push(amsiEvent))
		if err != nil {
			slog.Warn("etw: AMSI script content unavailable", "err", err)
		} else {
			s.sessions = append(s.sessions, ses)
		}
	}
	// Process access is optional: without it the rest still runs.
	if !off[GroupAccess] {
		ses, err := etw.Start(etw.Config{Name: "SIEMAgent-Access", Providers: []etw.Provider{{GUID: auditAPIProvider,
			EventIDs: []uint16{auditOpenProcess}}}}, push(accessEvent))
		if err != nil {
			slog.Warn("etw: process access telemetry unavailable", "err", err)
		} else {
			s.sessions = append(s.sessions, ses)
		}
	}

	devices := newDeviceMap()
	j := newProcessJoiner(processImagePath, devices.dosPath)
	j.onStart = opts.OnProcess
	files := newFileTracker(j, uint32(windows.GetCurrentProcessId()), longPathName)
	files.onFile = opts.OnFile
	access := newAccessTracker(j, uint32(windows.GetCurrentProcessId()))
	s.onScript = opts.OnScript
	go s.run(j, files, access, buf)
	return s, nil
}

func (s *Sensor) run(j *processJoiner, files *fileTracker, access *accessTracker, buf *buffer.Buffer) {
	defer close(s.done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	report := time.NewTicker(time.Minute)
	defer report.Stop()
	var reported, reportedWrites uint64
	emit := func(logType string, lines ...string) {
		for _, l := range lines {
			if l != "" {
				buf.Push(tailer.Encode(logType, l))
			}
		}
	}
	s.q.loop(s.stop, tick.C, report.C, loopHooks{
		stop: func() {
			emit(LogTypeProcess, j.flush(time.Now().Add(joinWindow))...)
			emitOut(buf, files.flushAll())
			emit(LogTypeAccess, access.flushAll()...)
		},
		handle: func(src source) {
			now := time.Now()
			switch src.kind {
			case writeEvent:
				files.writeSession(src.ev)
			case kernelProcess:
				emit(LogTypeProcess, j.kernel(src.ev, now)...)
			case providerProcess:
				if src.ev.ID == threadStartEvent {
					emit(LogTypeAccess, access.threadStart(src.ev, now))
				} else {
					emit(LogTypeProcess, j.provider(src.ev, now)...)
				}
			case accessEvent:
				emit(LogTypeAccess, access.openProcess(src.ev, now))
			case amsiEvent:
				if sc, ok := j.amsiScript(src.ev); ok && s.onScript != nil {
					s.onScript(sc)
				}
			case networkEvent:
				emit(LogTypeNetwork, j.network(src.ev))
			case dnsEvent:
				emit(LogTypeDNS, j.dns(src.ev))
			case fileEvent:
				emitOut(buf, files.file(src.ev))
			case imageEvent:
				emitOut(buf, files.image(src.ev))
			}
		},
		tick: func(now time.Time) {
			emit(LogTypeProcess, j.flush(now)...)
			emitOut(buf, files.tick())
			emit(LogTypeAccess, access.tick(now)...)
		},
		report: func() {
			d, w := s.q.dropped.Load(), s.q.writesDropped.Load()
			if d != reported || w != reportedWrites {
				slog.Warn("etw sensor dropped events: the agent fell behind", "dropped", d-reported,
					"writes_dropped", w-reportedWrites)
				emit(LogTypeStatus, statusLine(d-reported, d, w-reportedWrites, w))
				reported, reportedWrites = d, w
			}
		},
	})
}

func emitOut(buf *buffer.Buffer, lines []out) {
	for _, o := range lines {
		if o.line != "" {
			buf.Push(tailer.Encode(o.logType, o.line))
		}
	}
}

// longPathName expands 8.3 components (RUNNER~1) of p's directory, which
// still exists when the file itself was renamed away.
func longPathName(p string) string {
	dir, base := filepath.Split(p)
	if dir == "" {
		return p
	}
	in, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return p
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return p
	}
	return filepath.Join(windows.UTF16ToString(buf[:n]), base)
}

// Dropped is the number of SIEM events lost because the agent fell behind
// (the guard's file writes are counted apart, WritesDropped).
func (s *Sensor) Dropped() uint64 { return s.q.dropped.Load() }

// WritesDropped is the number of the guard's file writes lost because the
// agent fell behind.
func (s *Sensor) WritesDropped() uint64 { return s.q.writesDropped.Load() }

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
