//go:build !linux

package ransomguard

// Without the Linux sensor there are no per-process file events, so
// there is no process to stop: canary changes are reported only.
var killTree func(pid uint32) (int, error)
