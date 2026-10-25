//go:build windows

package etw

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Session is a running real-time session and its consumer.
type Session struct {
	name         string
	nameW        []uint16
	handle       uint64 // controller handle (StartTrace)
	trace        uint64 // consumer handle (OpenTrace)
	props        []uint64
	handler      func(*Event)
	done         chan struct{}
	id           uintptr
	once         sync.Once
	decodeErrors atomic.Uint64
}

var (
	sessionsMu sync.Mutex
	sessions   = map[uintptr]*Session{}
	nextID     uintptr
	// One callback for every session (NewCallback slots are limited); the
	// session is found through EVENT_RECORD.UserContext.
	recordCallback = windows.NewCallback(func(rec *eventRecord) uintptr {
		sessionsMu.Lock()
		s := sessions[rec.UserContext]
		sessionsMu.Unlock()
		if s != nil {
			ev, err := decode(rec)
			if err != nil {
				s.decodeErrors.Add(1)
			}
			if ev != nil {
				s.handler(ev)
			}
		}
		return 0
	})
)

// Start starts cfg as a real-time session and calls handle for every event,
// on the session's own goroutine, until Close. A session left over by an
// earlier process with the same name is stopped and replaced.
func Start(cfg Config, handle func(*Event)) (*Session, error) {
	if cfg.Name == "" {
		return nil, errors.New("etw: session name required")
	}
	if cfg.KernelFlags != 0 && len(cfg.Providers) > 0 {
		return nil, errors.New("etw: a kernel session takes no providers")
	}
	nameW, err := windows.UTF16FromString(cfg.Name)
	if err != nil {
		return nil, err
	}
	s := &Session{name: cfg.Name, nameW: nameW, handler: handle, done: make(chan struct{})}
	err = s.start(cfg)
	if errors.Is(err, errorAlreadyExists) { // left running by a process that died
		stopByName(nameW)
		err = s.start(cfg)
	}
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.Providers {
		if err := s.enable(p); err != nil {
			s.stop()
			return nil, err
		}
	}
	if err := s.consume(); err != nil {
		s.stop()
		return nil, err
	}
	return s, nil
}

func (s *Session) start(cfg Config) error {
	size := unsafe.Sizeof(eventTraceProperties{}) + uintptr(len(s.nameW))*2
	s.props = make([]uint64, (size+7)/8)
	p := (*eventTraceProperties)(unsafe.Pointer(&s.props[0]))
	p.Wnode.BufferSize = uint32(size)
	p.Wnode.Flags = wnodeFlagTracedGUID
	p.Wnode.ClientContext = 2 // timestamps in system time (FILETIME)
	guid, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	p.Wnode.GUID = guid
	p.LogFileMode = eventTraceRealTimeMode
	if cfg.KernelFlags != 0 {
		p.LogFileMode |= eventTraceSystemLoggerMode
		p.EnableFlags = cfg.KernelFlags
	}
	p.BufferSize = 64 // KiB
	p.MinimumBuffers = 8
	p.MaximumBuffers = 64
	p.FlushTimer = 1 // seconds: bounds the delay before a quiet buffer is delivered
	p.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(&s.nameW[0])), uintptr(unsafe.Pointer(p)))
	if r != 0 {
		return fmt.Errorf("etw: StartTrace %s: %w", s.name, syscall.Errno(r))
	}
	return nil
}

func (s *Session) enable(p Provider) error {
	guid, err := windows.GUIDFromString(p.GUID)
	if err != nil {
		return fmt.Errorf("etw: provider %q: %w", p.GUID, err)
	}
	level := p.Level
	if level == 0 {
		level = 5
	}
	keywords := p.Keywords
	if keywords == 0 {
		keywords = ^uint64(0)
	}
	r, _, _ := procEnableTraceEx2.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&guid)), eventControlCodeEnableProvider,
		uintptr(level), uintptr(keywords), 0, 0, 0)
	if r != 0 {
		return fmt.Errorf("etw: enable %s in %s: %w", p.GUID, s.name, syscall.Errno(r))
	}
	return nil
}

func (s *Session) consume() error {
	sessionsMu.Lock()
	nextID++
	s.id = nextID
	sessions[s.id] = s
	sessionsMu.Unlock()

	lf := eventTraceLogfile{
		LoggerName:          &s.nameW[0],
		ProcessTraceMode:    processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: recordCallback,
		Context:             s.id,
	}
	r, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(&lf)))
	if uint64(r) == invalidProcessTraceHandle {
		s.unregister()
		return fmt.Errorf("etw: OpenTrace %s: %w", s.name, err)
	}
	s.trace = uint64(r)
	go func() {
		defer close(s.done)
		// Blocks, calling recordCallback, until the session stops or CloseTrace.
		procProcessTrace.Call(uintptr(unsafe.Pointer(&s.trace)), 1, 0, 0)
	}()
	return nil
}

// Close stops the session and waits for its consumer to finish.
func (s *Session) Close() error {
	s.once.Do(func() {
		s.stop()
		if s.trace != 0 {
			procCloseTrace.Call(uintptr(s.trace))
			select {
			case <-s.done:
			case <-time.After(10 * time.Second):
			}
		}
		s.unregister()
	})
	return nil
}

// DecodeErrors counts events TDH could not describe (delivered partially or not).
func (s *Session) DecodeErrors() uint64 { return s.decodeErrors.Load() }

func (s *Session) stop() {
	p := (*eventTraceProperties)(unsafe.Pointer(&s.props[0]))
	procControlTraceW.Call(uintptr(s.handle), 0, uintptr(unsafe.Pointer(p)), eventTraceControlStop)
}

func (s *Session) unregister() {
	sessionsMu.Lock()
	delete(sessions, s.id)
	sessionsMu.Unlock()
}

// stopByName stops a session left running by a process that died.
func stopByName(nameW []uint16) {
	size := unsafe.Sizeof(eventTraceProperties{}) + uintptr(len(nameW))*2 + 1024
	buf := make([]uint64, (size+7)/8)
	p := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	p.Wnode.BufferSize = uint32(size)
	p.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(&nameW[0])), uintptr(unsafe.Pointer(p)), eventTraceControlStop)
}
