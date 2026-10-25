//go:build windows

package winevent

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modwevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modwevtapi.NewProc("EvtNext")
	procEvtRender    = modwevtapi.NewProc("EvtRender")
	procEvtClose     = modwevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
	errNoMoreItems             = syscall.Errno(259) // ERROR_NO_MORE_ITEMS
	errInsufficientBuffer      = syscall.Errno(122) // ERROR_INSUFFICIENT_BUFFER
	batchSize                  = 64
)

// Subscribe streams new events from channel (e.g. "Security",
// "Microsoft-Windows-Sysmon/Operational") to emit as FormatXML lines until
// stop is closed. Like the file tailer, it starts at "now": history before the
// agent started is not replayed. Reading Security needs Administrator/SYSTEM.
func Subscribe(channel string, emit func(line string), stop <-chan struct{}) error {
	signal, err := windows.CreateEvent(nil, 1, 1, nil) // manual-reset, initially signalled
	if err != nil {
		return fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(signal)

	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return err
	}
	query, _ := windows.UTF16PtrFromString("*")
	sub, _, callErr := procEvtSubscribe.Call(
		0, uintptr(signal), uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(query)),
		0, 0, 0, evtSubscribeToFutureEvents,
	)
	if sub == 0 {
		return fmt.Errorf("EvtSubscribe(%s): %w", channel, callErr)
	}
	defer procEvtClose.Call(sub)

	handles := make([]uintptr, batchSize)
	buf := make([]uint16, 16*1024)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		ev, _ := windows.WaitForSingleObject(signal, 1000)
		if ev == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		for {
			var returned uint32
			ok, _, nextErr := procEvtNext.Call(sub, batchSize, uintptr(unsafe.Pointer(&handles[0])), 0, 0,
				uintptr(unsafe.Pointer(&returned)))
			if ok == 0 {
				if errors.Is(nextErr, errNoMoreItems) {
					windows.ResetEvent(signal)
					break
				}
				return fmt.Errorf("EvtNext(%s): %w", channel, nextErr)
			}
			for _, h := range handles[:returned] {
				raw, rerr := render(h, &buf)
				procEvtClose.Call(h)
				if rerr != nil {
					continue
				}
				if line, ferr := FormatXML([]byte(raw)); ferr == nil {
					emit(line)
				}
			}
		}
	}
}

// render returns the event as XML, growing buf when the event is larger.
func render(h uintptr, buf *[]uint16) (string, error) { return renderAs(h, evtRenderEventXML, buf) }

// renderAs renders an event (evtRenderEventXML) or a bookmark (evtRenderBookmark).
func renderAs(h uintptr, flags uintptr, buf *[]uint16) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		b := *buf
		var used, props uint32
		ok, _, err := procEvtRender.Call(0, h, flags, uintptr(len(b)*2),
			uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if ok != 0 {
			return windows.UTF16ToString(b[:used/2]), nil
		}
		if !errors.Is(err, errInsufficientBuffer) {
			return "", err
		}
		*buf = make([]uint16, used/2+1)
	}
	return "", errors.New("EvtRender: event larger than its reported size")
}
