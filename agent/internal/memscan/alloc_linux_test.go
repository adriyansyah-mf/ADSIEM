//go:build linux

package memscan

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func allocRWX(t *testing.T) (addr, size uint64, free func()) {
	b, err := unix.Mmap(-1, 0, 8192, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Skipf("cannot map RWX memory here: %v", err)
	}
	b[0] = 0xc3 // ret
	return uint64(uintptr(unsafe.Pointer(&b[0]))), 8192, func() { unix.Munmap(b) }
}
