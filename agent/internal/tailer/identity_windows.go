//go:build windows

package tailer

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// fileIdentity is the volume serial number plus the NTFS file index: stable
// across renames, different for a new file created at the same path.
func fileIdentity(f *os.File) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}
