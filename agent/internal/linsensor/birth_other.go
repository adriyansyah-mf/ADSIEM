//go:build !linux

package linsensor

import "time"

// fileBirth: the Linux sensor only runs on Linux.
func fileBirth(string) (time.Time, bool) { return time.Time{}, false }
