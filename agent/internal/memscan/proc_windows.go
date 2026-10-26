//go:build windows

package memscan

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	psapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetMappedFileName = psapi.NewProc("GetMappedFileNameW")
)

const (
	memCommit  = 0x1000
	memImage   = 0x1000000
	memMapped  = 0x40000
	pageGuard  = 0x100
	pageNoAcc  = 0x01
	maxUserVA  = 0x7FFFFFFFFFFF
	queryFlags = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
)

// perms maps a PAGE_* protection to "rwx" letters.
func perms(protect uint32) string {
	switch protect &^ (pageGuard | 0x200 | 0x400) { // guard, nocache, writecombine
	case windows.PAGE_READONLY:
		return "r--"
	case windows.PAGE_READWRITE, windows.PAGE_WRITECOPY:
		return "rw-"
	case windows.PAGE_EXECUTE:
		return "--x"
	case windows.PAGE_EXECUTE_READ:
		return "r-x"
	case windows.PAGE_EXECUTE_READWRITE, windows.PAGE_EXECUTE_WRITECOPY:
		return "rwx"
	}
	return "---"
}

func mappedFile(h windows.Handle, addr uintptr) string {
	buf := make([]uint16, windows.MAX_PATH)
	n, _, _ := procGetMappedFileName.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// Regions walks the committed regions with VirtualQueryEx.
func Regions(pid int) ([]Region, error) {
	h, err := windows.OpenProcess(queryFlags, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	var out []Region
	var mbi windows.MemoryBasicInformation
	for addr := uintptr(0); addr < maxUserVA; {
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		if mbi.State == memCommit && mbi.Protect&(pageGuard|pageNoAcc) == 0 {
			r := Region{Start: uint64(mbi.BaseAddress), End: uint64(next), Perms: perms(mbi.Protect), Kind: "private"}
			switch mbi.Type {
			case memImage:
				r.Kind, r.Path = "image", mappedFile(h, mbi.BaseAddress)
			case memMapped:
				r.Kind, r.Path = "mapped", mappedFile(h, mbi.BaseAddress)
			}
			out = append(out, r)
		}
		addr = next
	}
	return out, nil
}

type winMem struct{ h windows.Handle }

func (m winMem) ReadAt(p []byte, addr uint64) (int, error) {
	var n uintptr
	err := windows.ReadProcessMemory(m.h, uintptr(addr), &p[0], uintptr(len(p)), &n)
	if n > 0 {
		return int(n), nil
	}
	return 0, err
}

func (m winMem) Close() error { return windows.CloseHandle(m.h) }

// Reader reads another process's memory.
type Reader interface {
	ReadAt(p []byte, addr uint64) (int, error)
	Close() error
}

// Open opens pid for reading (SYSTEM can read every process except
// protected ones).
func Open(pid int) (Reader, error) {
	h, err := windows.OpenProcess(queryFlags, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	return winMem{h}, nil
}

// ProcessImage is the executable path of pid.
func ProcessImage(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// Processes lists processes from a toolhelp snapshot.
func Processes() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []Proc
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == 0 || e.ProcessID == 4 { // idle, System
			continue
		}
		img := ProcessImage(int(e.ProcessID))
		if img == "" {
			img = windows.UTF16ToString(e.ExeFile[:])
		}
		out = append(out, Proc{PID: int(e.ProcessID), Image: img})
	}
	if err != syscall.ERROR_NO_MORE_FILES {
		return out, fmt.Errorf("process snapshot: %w", err)
	}
	return out, nil
}
