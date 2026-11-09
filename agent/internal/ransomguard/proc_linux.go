//go:build linux

package ransomguard

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// liveProcs looks processes up in /proc: the parent from stat, the image
// from the exe link ("" for a kernel thread or a process we cannot read).
func liveProcs() procLookup {
	return func(pid uint32) (proc, bool) {
		dir := "/proc/" + strconv.FormatUint(uint64(pid), 10)
		b, err := os.ReadFile(dir + "/stat")
		if err != nil {
			return proc{}, false
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			return proc{}, false
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			return proc{}, false
		}
		ppid, _ := strconv.ParseUint(f[1], 10, 32)
		exe, _ := os.Readlink(dir + "/exe")
		return proc{pid: pid, ppid: uint32(ppid), image: strings.TrimSuffix(exe, " (deleted)")}, true
	}
}

// procCwd is a process's working directory ("" when unknown).
func procCwd(pid uint32) string {
	d, _ := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cwd")
	return d
}

// fileRootOwned reports whether p is a file owned by root (false when it
// cannot be read).
func fileRootOwned(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// runSystemCmd: nothing to revert on Linux.
var runSystemCmd func(name string, args ...string) error
