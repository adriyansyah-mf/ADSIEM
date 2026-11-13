//go:build windows

package task

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hostTarget: Windows has no mount namespaces; a reported path is the file.
func hostTarget(path string) (string, error) { return filepath.Abs(filepath.Clean(path)) }

// processesRunning lists the processes whose image is path (case-insensitive,
// as Windows paths are).
func processesRunning(path string) []int {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var pids []int
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		pid := pe.ProcessID
		if pid == 0 || pid == 4 {
			continue
		}
		if image := imagePath(pid); image != "" && strings.EqualFold(image, abs) {
			pids = append(pids, int(pid))
		}
	}
	return pids
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
