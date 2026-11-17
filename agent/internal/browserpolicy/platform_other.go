//go:build !windows

package browserpolicy

import (
	"path/filepath"
	"runtime"
)

// New is the applier for this OS: managed-policy files on Linux; nothing
// elsewhere.
func New(stateDir string) Applier {
	if runtime.GOOS != "linux" {
		return nil
	}
	return &FileApplier{Root: "/", StatePath: filepath.Join(stateDir, "browser_policy.json")}
}
