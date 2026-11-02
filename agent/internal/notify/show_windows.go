//go:build windows

package notify

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procWTSSendMessage = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSSendMessageW")

const (
	mbOK            = 0x0
	mbIconWarning   = 0x30
	mbSetForeground = 0x10000
	mbTopmost       = 0x40000
	showSeconds     = 120 // the box closes itself after this
)

var platformShow = func(title, message string) error {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return fmt.Errorf("enumerate sessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	list := unsafe.Slice(sessions, count)
	t, err := windows.UTF16FromString(title)
	if err != nil {
		return err
	}
	m, err := windows.UTF16FromString(message)
	if err != nil {
		return err
	}
	shown := 0
	for _, s := range list {
		if s.State != windows.WTSActive || s.SessionID == 0 {
			continue
		}
		var response uint32
		r, _, callErr := procWTSSendMessage.Call(0, uintptr(s.SessionID),
			uintptr(unsafe.Pointer(&t[0])), uintptr(2*(len(t)-1)),
			uintptr(unsafe.Pointer(&m[0])), uintptr(2*(len(m)-1)),
			mbOK|mbIconWarning|mbSetForeground|mbTopmost, showSeconds,
			uintptr(unsafe.Pointer(&response)), 0) // bWait FALSE: do not wait for the user
		if r == 0 {
			err = callErr
			continue
		}
		shown++
	}
	if shown == 0 && err != nil {
		return fmt.Errorf("WTSSendMessage: %w", err)
	}
	return nil
}
