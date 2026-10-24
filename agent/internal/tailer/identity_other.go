//go:build !linux && !windows

package tailer

import (
	"os"

	"github.com/siem-platform/agent/internal/evidence"
)

func openLog(path string) (*os.File, error) { return os.Open(path) }

// Durable file cursors need a platform file identity; the agent ships for
// Linux and Windows only.
func fileIdentity(*os.File) (string, error) { return "", evidence.ErrUnsupported }
