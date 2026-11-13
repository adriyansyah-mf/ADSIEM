//go:build linux

package task

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processesRunning lists the processes whose executable is path: /proc/<pid>/exe
// points at it, or at "<path> (deleted)" once the program removed its file
// (droppers often do, and keep running from memory).
func processesRunning(path string) []int {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue // kernel thread, gone, or not ours to read
		}
		if exe == abs || strings.TrimSuffix(exe, " (deleted)") == abs {
			pids = append(pids, pid)
		}
	}
	return pids
}
