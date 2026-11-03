package fullscan

import "golang.org/x/sys/windows"

const (
	threadModeBackgroundBegin = 0x00010000
	threadModeBackgroundEnd   = 0x00020000
)

var procSetThreadPriority = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadPriority")

func setThreadPriority(h windows.Handle, p uintptr) bool {
	r, _, _ := procSetThreadPriority.Call(uintptr(h), p)
	return r != 0
}

// lowPriority puts the calling (locked) thread in background mode: low CPU
// priority and low I/O and memory priority.
func lowPriority() func() {
	h := windows.CurrentThread()
	if !setThreadPriority(h, threadModeBackgroundBegin) {
		return func() {}
	}
	return func() { setThreadPriority(h, threadModeBackgroundEnd) }
}
