//go:build linux

package task

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// protectedComms can never be killed by a task, whatever the request says.
// An analyst killing the agent's own supervisor chain (or PID 1) takes the
// endpoint off the network with no way back short of a console.
var protectedComms = map[string]struct{}{
	"systemd":  {},
	"init":     {},
	"containerd": {},
	"dockerd":  {},
}

const (
	defaultKillGrace = 5 * time.Second
	maxKillGrace     = 60 * time.Second
)

func killProcess(pid int, force bool, graceSeconds float64) (KillResult, error) {
	res := KillResult{PID: pid}

	if pid <= 0 {
		return res, fmt.Errorf("kill_process: invalid pid %d", pid)
	}
	if pid == 1 {
		res.Refused = "pid 1 is the init process and cannot be terminated"
		return res, fmt.Errorf("kill_process: %s", res.Refused)
	}
	if pid == os.Getpid() {
		res.Refused = "refusing to kill the agent's own process"
		return res, fmt.Errorf("kill_process: %s", res.Refused)
	}

	comm, err := readComm(pid)
	if err != nil {
		return res, fmt.Errorf("kill_process: pid %d: %w", pid, err)
	}
	res.Comm = comm

	if _, blocked := protectedComms[comm]; blocked {
		res.Refused = fmt.Sprintf("process %q is protected", comm)
		return res, fmt.Errorf("kill_process: %s", res.Refused)
	}
	if isAncestor(pid) {
		res.Refused = "refusing to kill an ancestor of the agent"
		return res, fmt.Errorf("kill_process: %s", res.Refused)
	}

	grace := time.Duration(graceSeconds) * time.Second
	if grace <= 0 {
		grace = defaultKillGrace
	}
	if grace > maxKillGrace {
		grace = maxKillGrace
	}

	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return res, fmt.Errorf("kill_process: SIGTERM %d: %w", pid, err)
	}
	res.Signal = "TERM"

	start := time.Now()
	exited := waitGone(pid, grace)
	res.Exited = exited
	res.WaitMS = time.Since(start).Milliseconds()

	if exited || !force {
		return res, nil
	}

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return res, fmt.Errorf("kill_process: SIGKILL %d: %w", pid, err)
	}
	res.Signal = "KILL"
	res.Forced = true
	res.Exited = waitGone(pid, 2*time.Second)
	res.WaitMS = time.Since(start).Milliseconds()
	return res, nil
}

func waitGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func readComm(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// isAncestor walks the agent's own parent chain; killing a parent would take
// the agent down with it.
func isAncestor(pid int) bool {
	current := os.Getpid()
	for i := 0; i < 32; i++ {
		ppid, err := parentPID(current)
		if err != nil || ppid <= 0 {
			return false
		}
		if ppid == pid {
			return true
		}
		if ppid == current {
			return false
		}
		current = ppid
	}
	return false
}

func parentPID(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	stat := string(data)
	closeIdx := strings.LastIndex(stat, ")")
	if closeIdx < 0 {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	fields := strings.Fields(stat[closeIdx+1:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	return strconv.Atoi(fields[1])
}

func resolveExe(pid int) string {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return exe
}
