//go:build !windows

package evidence

import "syscall"

// processCPUSeconds is this process's user + system CPU time.
func processCPUSeconds() float64 {
	var u syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &u) != nil {
		return 0
	}
	return float64(u.Utime.Sec+u.Stime.Sec) + float64(u.Utime.Usec+u.Stime.Usec)/1e6
}

// peakRSSBytes is the process's peak resident set (Linux reports KiB).
func peakRSSBytes() int64 {
	var u syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &u) != nil {
		return 0
	}
	return int64(u.Maxrss) * 1024
}
