//go:build windows

package ransomguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// criticalImages never die, when they run from the system directory:
// terminating them crashes or locks up Windows (the same list as the
// kill_process task, internal/task/response_windows.go). The same name
// anywhere else is not the real thing and may be killed.
var criticalImages = map[string]bool{
	"smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "lsass.exe": true, "lsaiso.exe": true, "svchost.exe": true,
	"fontdrvhost.exe": true, "dwm.exe": true, "lsm.exe": true, "memcompression": true,
	"registry": true, "secure system": true,
}

// killTree terminates pid, then its descendants, children before the
// snapshot can change much: TerminateProcess is immediate, so the root
// stops encrypting first. It refuses System (4), critical processes, the
// agent and the agent's ancestors (the service host).
func killTree(pid uint32) (int, error) {
	if pid <= 4 {
		return 0, errors.New("refusing to kill the System process")
	}
	parents, err := processParents()
	if err != nil {
		return 0, err
	}
	self := uint32(os.Getpid())
	for p, i := self, 0; i < 32; i++ {
		if p == pid {
			return 0, errors.New("refusing to kill the agent or one of its ancestors")
		}
		pp, ok := parents[p]
		if !ok || pp == 0 || pp == p {
			break
		}
		p = pp
	}
	if critical(pid) {
		return 0, fmt.Errorf("refusing to kill pid %d: a critical Windows process", pid)
	}
	children := map[uint32][]uint32{}
	for c, p := range parents {
		children[p] = append(children[p], c)
	}
	tree := []uint32{pid}
	for i := 0; i < len(tree) && len(tree) < 4096; i++ {
		for _, c := range children[tree[i]] {
			if c != self && c != tree[i] {
				tree = append(tree, c)
			}
		}
	}
	killed := 0
	var firstErr error
	for i, p := range tree {
		if i > 0 && critical(p) {
			continue
		}
		if err := terminate(p); err != nil {
			if i == 0 {
				return 0, err
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		killed++
	}
	return killed, firstErr
}

func terminate(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate pid %d: %w", pid, err)
	}
	return nil
}

// critical: a critical name running from the system directory, or a
// process that cannot be classified (refuse rather than risk the host).
func critical(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false // gone, or terminate will fail and say so
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return true
	}
	image := windows.UTF16ToString(buf[:n])
	if !criticalImages[strings.ToLower(filepath.Base(image))] {
		return false
	}
	sys, err := windows.GetSystemDirectory()
	return err != nil || strings.EqualFold(filepath.Dir(image), sys)
}

func processParents() (map[uint32]uint32, error) {
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
