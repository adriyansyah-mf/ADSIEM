//go:build windows

package ransomguard

import (
	"context"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// liveProcs looks processes up in one Toolhelp snapshot (taken at the
// first lookup) and their full image path with QueryFullProcessImageName
// ("" when the process cannot be opened: System, protected processes).
func liveProcs() procLookup {
	var parents map[uint32]uint32
	taken := false
	return func(pid uint32) (proc, bool) {
		if !taken {
			parents, _ = processParents()
			taken = true
		}
		pp, ok := parents[pid]
		if !ok {
			return proc{}, false
		}
		return proc{pid: pid, ppid: pp, image: imagePath(pid)}, true
	}
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func procCwd(uint32) string { return "" }

// runSystemCmd runs a program from the system directory (bcdedit.exe).
var runSystemCmd = func(name string, args ...string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, filepath.Join(sys, name+".exe"), args...).Run()
}
