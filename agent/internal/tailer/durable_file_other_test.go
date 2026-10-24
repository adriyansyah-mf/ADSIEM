//go:build !windows

package tailer

import "os"

// openAppendShared opens path for appending; POSIX renames never conflict
// with open handles.
func openAppendShared(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
}
