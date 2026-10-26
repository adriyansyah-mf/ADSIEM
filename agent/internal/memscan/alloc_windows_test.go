//go:build windows

package memscan

import (
	"testing"

	"golang.org/x/sys/windows"
)

func allocRWX(t *testing.T) (addr, size uint64, free func()) {
	p, err := windows.VirtualAlloc(0, 8192, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		t.Skipf("cannot allocate RWX memory here: %v", err)
	}
	return uint64(p), 8192, func() { windows.VirtualFree(p, 0, windows.MEM_RELEASE) }
}
