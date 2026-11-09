//go:build !windows

package ransomguard

import "os"

// isLink reports whether path itself is a symbolic link.
func isLink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}
