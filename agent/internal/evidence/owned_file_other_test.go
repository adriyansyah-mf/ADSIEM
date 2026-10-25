//go:build !windows

package evidence

import "os"

// writeOwned writes a crash-simulation file; ownership needs no fixing here.
func writeOwned(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
