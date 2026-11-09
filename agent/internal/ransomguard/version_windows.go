//go:build windows

package ransomguard

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// originalFilename is the PE OriginalFilename version string of a file
// ("" when it has none), cached: a renamed copy of vssadmin.exe still says
// VSSADMIN.EXE.
var originalFilename = newNameCache(readOriginalFilename)

func readOriginalFilename(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 || size > 1<<20 {
		return ""
	}
	buf := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])) != nil {
		return ""
	}
	var trans unsafe.Pointer
	var n uint32
	if windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&trans), &n) != nil || n < 4 {
		return ""
	}
	pairs := unsafe.Slice((*uint16)(trans), n/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		sub := fmt.Sprintf(`\StringFileInfo\%04x%04x\OriginalFilename`, pairs[i], pairs[i+1])
		var val unsafe.Pointer
		var vn uint32
		if windows.VerQueryValue(unsafe.Pointer(&buf[0]), sub, unsafe.Pointer(&val), &vn) != nil || vn == 0 {
			continue
		}
		return windows.UTF16ToString(unsafe.Slice((*uint16)(val), vn))
	}
	return ""
}
