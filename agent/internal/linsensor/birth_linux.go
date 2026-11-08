//go:build linux

package linsensor

import (
	"time"

	"golang.org/x/sys/unix"
)

// fileBirth is path's creation time from statx (STATX_BTIME), when the
// filesystem records one (ext4, xfs, btrfs; not all). Without it the open
// keeps the action its flags give.
func fileBirth(path string) (time.Time, bool) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_DONT_SYNC, unix.STATX_BTIME, &st); err != nil {
		return time.Time{}, false
	}
	if st.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}, false
	}
	return time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)), true
}
