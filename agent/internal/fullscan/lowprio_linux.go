package fullscan

import (
	"syscall"
)

// ioprio_set(IOPRIO_WHO_PROCESS, tid, IOPRIO_CLASS_IDLE): this thread only.
const (
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	ioprioClassShift = 13
)

// lowPriority puts the calling (locked) thread at nice 19 and idle I/O.
func lowPriority() func() {
	tid := syscall.Gettid()
	oldNice, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid)
	niced := err == nil && syscall.Setpriority(syscall.PRIO_PROCESS, tid, 19) == nil
	_, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<ioprioClassShift)
	return func() {
		if niced {
			// getpriority returns 20-nice on Linux
			syscall.Setpriority(syscall.PRIO_PROCESS, tid, 20-oldNice)
		}
		if errno == 0 {
			// back to the default (best effort, from the nice value)
			syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), 0)
		}
	}
}
