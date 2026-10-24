//go:build windows

package winevent

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procEvtCreateBookmark = modwevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = modwevtapi.NewProc("EvtUpdateBookmark")
)

const (
	evtRenderBookmark   = 2
	errInvalidOperation = syscall.Errno(4317) // ERROR_INVALID_OPERATION
)

// SubscribeResume streams channel events strictly after resume, each with the
// bookmark just past it, until ctx ends (returning ctx.Err()). A bookmark that
// no longer names a retained event returns ErrBookmarkGap. An emit error stops
// it and is returned unchanged.
func SubscribeResume(ctx context.Context, channel string, resume Resume, emit func(Event) error) error {
	return subscribeResume(ctx, &windowsAPI{}, channel, resume, emit)
}

// Baseline bookmarks channel's newest retained event, or reports it empty.
func Baseline(ctx context.Context, channel string) (Resume, error) {
	if err := ctx.Err(); err != nil {
		return Resume{}, err
	}
	return baseline(&windowsAPI{}, channel)
}

// windowsAPI is nativeAPI over wevtapi.dll. One render buffer per subscription.
type windowsAPI struct{ buf []uint16 }

func (w *windowsAPI) buffer() *[]uint16 {
	if w.buf == nil {
		w.buf = make([]uint16, 16*1024)
	}
	return &w.buf
}

type windowsSubscription struct {
	h      uintptr
	signal windows.Handle
}

func (w *windowsAPI) subscribe(channel string, bookmark handle, flags uint32) (subscription, error) {
	signal, err := windows.CreateEvent(nil, 1, 1, nil) // manual-reset, initially signalled
	if err != nil {
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		windows.CloseHandle(signal)
		return nil, err
	}
	query, _ := windows.UTF16PtrFromString("*")
	sub, _, callErr := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(ch)),
		uintptr(unsafe.Pointer(query)), uintptr(bookmark), 0, 0, uintptr(flags))
	if sub == 0 {
		windows.CloseHandle(signal)
		return nil, callErr
	}
	return &windowsSubscription{h: sub, signal: signal}, nil
}

func (s *windowsSubscription) wait(timeout time.Duration) error {
	if _, err := windows.WaitForSingleObject(s.signal, uint32(timeout/time.Millisecond)); err != nil {
		return err
	}
	return nil
}

func (s *windowsSubscription) next(max int) ([]handle, error) {
	raw := make([]uintptr, max)
	var returned uint32
	ok, _, err := procEvtNext.Call(s.h, uintptr(max), uintptr(unsafe.Pointer(&raw[0])), 0, 0,
		uintptr(unsafe.Pointer(&returned)))
	if ok == 0 {
		// A subscription with nothing (yet) to deliver, e.g. on an empty
		// channel, reports ERROR_INVALID_OPERATION instead of no-more-items.
		if errors.Is(err, errNoMoreItems) || errors.Is(err, errInvalidOperation) {
			windows.ResetEvent(s.signal)
			return nil, nil
		}
		return nil, err
	}
	out := make([]handle, returned)
	for i := range out {
		out[i] = handle(raw[i])
	}
	return out, nil
}

func (s *windowsSubscription) close() {
	procEvtClose.Call(s.h)
	windows.CloseHandle(s.signal)
}

func (w *windowsAPI) renderXML(h handle) (string, error) {
	return renderAs(uintptr(h), evtRenderEventXML, w.buffer())
}

func (w *windowsAPI) renderBookmark(bm handle) (string, error) {
	return renderAs(uintptr(bm), evtRenderBookmark, w.buffer())
}

func (w *windowsAPI) createBookmark(xml string) (handle, error) {
	var p *uint16
	if xml != "" {
		var err error
		if p, err = windows.UTF16PtrFromString(xml); err != nil {
			return 0, err
		}
	}
	h, _, err := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if h == 0 {
		return 0, err
	}
	return handle(h), nil
}

func (w *windowsAPI) updateBookmark(bm, ev handle) error {
	if ok, _, err := procEvtUpdateBookmark.Call(uintptr(bm), uintptr(ev)); ok == 0 {
		return err
	}
	return nil
}

func (w *windowsAPI) latest(channel string) (handle, bool, error) {
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, false, err
	}
	query, _ := windows.UTF16PtrFromString("*")
	rs, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(query)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if rs == 0 {
		return 0, false, callErr
	}
	defer procEvtClose.Call(rs)
	var h uintptr
	var returned uint32
	ok, _, nextErr := procEvtNext.Call(rs, 1, uintptr(unsafe.Pointer(&h)), 1000, 0, uintptr(unsafe.Pointer(&returned)))
	if ok == 0 {
		if errors.Is(nextErr, errNoMoreItems) {
			return 0, false, nil
		}
		return 0, false, nextErr
	}
	return handle(h), returned == 1, nil
}

func (w *windowsAPI) close(h handle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}
