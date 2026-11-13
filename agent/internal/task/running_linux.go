//go:build linux

package task

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/siem-platform/agent/internal/mountns"
)

// processesRunning lists the processes whose executable is path. A process
// runs the file when /proc/<pid>/exe is the same inode, which holds whatever
// path the process sees it under: a process in another mount namespace
// (systemd PrivateTmp, a container) names apache's /var/tmp/x what the host
// calls /var/tmp/systemd-private-.../tmp/x. A program that removed its file
// (droppers often do, and keep running from memory) still matches by the
// "<path> (deleted)" link.
func processesRunning(path string) []int {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	var dev, ino uint64
	if fi, err := os.Stat(abs); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			dev, ino = uint64(st.Dev), st.Ino
		}
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
		exe := "/proc/" + e.Name() + "/exe"
		if ino != 0 {
			if fi, err := os.Stat(exe); err == nil {
				if st, ok := fi.Sys().(*syscall.Stat_t); ok && uint64(st.Dev) == dev && st.Ino == ino {
					pids = append(pids, pid)
					continue
				}
			}
		}
		link, err := os.Readlink(exe)
		if err != nil {
			continue // kernel thread, gone, or not ours to read
		}
		if link == abs || strings.TrimSuffix(link, " (deleted)") == abs {
			pids = append(pids, pid)
		}
	}
	return pids
}

// hostTarget is the file a response should act on. Sensors report paths as
// the process saw them; for a process in another mount namespace that path
// does not exist on the host (or is another file), so when path is missing
// the processes' namespaces are searched for it. One match is used: the file
// a process runs under that name if there is one, else the only file of that
// name. Several are refused rather than guessed.
func hostTarget(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(abs); err == nil {
		return abs, nil
	}
	cands := mountns.Locate(abs)
	var running []string
	for _, c := range cands {
		if c.Running {
			running = append(running, c.Path)
		}
	}
	switch {
	case len(running) == 1:
		return running[0], nil
	case len(running) == 0 && len(cands) == 1:
		return cands[0].Path, nil
	case len(cands) == 0:
		return abs, nil // let the caller report the missing file
	}
	all := make([]string, 0, len(cands))
	for _, c := range cands {
		all = append(all, c.Path)
	}
	return "", fmt.Errorf("%s names several files in other mount namespaces (%s); quarantine one of them by its host path",
		abs, strings.Join(all, ", "))
}
