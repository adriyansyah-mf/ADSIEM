//go:build windows

package task

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// criticalImages can never be killed when they run from the system directory:
// terminating any of them crashes or locks up Windows (csrss, wininit and
// smss are critical processes; lsass takes authentication down with it). The
// same name running from anywhere else is not the real thing and may be
// killed, since malware likes these names.
var criticalImages = map[string]struct{}{
	"smss.exe": {}, "csrss.exe": {}, "wininit.exe": {}, "winlogon.exe": {},
	"services.exe": {}, "lsass.exe": {}, "lsaiso.exe": {}, "svchost.exe": {},
	"fontdrvhost.exe": {}, "dwm.exe": {}, "lsm.exe": {}, "memcompression": {},
	"registry": {}, "secure system": {},
}

const (
	defaultKillGrace = 5 * time.Second
	maxKillGrace     = 60 * time.Second
)

// killProcess terminates pid. Windows has no polite stop for an arbitrary
// process (services and console programs have no window to close), so it is
// always TerminateProcess; force has nothing to escalate to. grace bounds the
// wait for the process to be gone.
func killProcess(pid int, force bool, graceSeconds float64) (KillResult, error) {
	res := KillResult{PID: pid, Signal: "TerminateProcess", Forced: true}
	refuse := func(why string) (KillResult, error) {
		res.Refused = why
		return res, fmt.Errorf("kill_process: %s", why)
	}
	switch {
	case pid <= 0:
		return res, fmt.Errorf("kill_process: invalid pid %d", pid)
	case pid == 4:
		return refuse("pid 4 is the System process")
	case pid == os.Getpid():
		return refuse("refusing to kill the agent's own process")
	}

	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return res, fmt.Errorf("kill_process: open pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	image, err := processImage(h)
	if err != nil {
		return res, fmt.Errorf("kill_process: pid %d image: %w", pid, err)
	}
	res.Image, res.Comm = image, filepath.Base(image)
	if isCriticalImage(image) {
		return refuse(fmt.Sprintf("process %q is a critical Windows process", res.Comm))
	}
	if isAncestor(pid) {
		return refuse("refusing to kill an ancestor of the agent")
	}

	grace := time.Duration(graceSeconds * float64(time.Second))
	if grace <= 0 {
		grace = defaultKillGrace
	}
	if grace > maxKillGrace {
		grace = maxKillGrace
	}
	start := time.Now()
	if err := windows.TerminateProcess(h, 1); err != nil {
		return res, fmt.Errorf("kill_process: TerminateProcess %d: %w", pid, err)
	}
	ev, err := windows.WaitForSingleObject(h, uint32(grace.Milliseconds()))
	res.Exited = err == nil && ev == windows.WAIT_OBJECT_0
	res.WaitMS = time.Since(start).Milliseconds()
	return res, nil
}

func processImage(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// isCriticalImage: a critical name running from the system directory.
func isCriticalImage(image string) bool {
	name := strings.ToLower(filepath.Base(image))
	if _, ok := criticalImages[name]; !ok {
		return false
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return true // cannot tell: refuse rather than risk the host
	}
	return strings.EqualFold(filepath.Dir(image), sys)
}

// isAncestor walks the agent's parent chain (services.exe for the service);
// killing a parent would take the agent down with it.
func isAncestor(pid int) bool {
	parents, err := parentPIDs()
	if err != nil {
		return true // cannot tell: refuse
	}
	current := uint32(os.Getpid())
	for i := 0; i < 32; i++ {
		ppid, ok := parents[current]
		if !ok || ppid == 0 || ppid == current {
			return false
		}
		if ppid == uint32(pid) {
			return true
		}
		current = ppid
	}
	return false
}

func parentPIDs() (map[uint32]uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	parents := map[uint32]uint32{}
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		parents[e.ProcessID] = e.ParentProcessID
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return parents, nil
}
