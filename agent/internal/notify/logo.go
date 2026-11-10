package notify

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

//go:embed assets/logo.png
var LogoPNG []byte

var (
	logoOnce sync.Once
	logoPath string
)

// EnsureLogo extracts the embedded platform logo to a persistent path on disk
// so that notification services (Windows WinRT Toast, Linux notify-send) can access it.
func EnsureLogo() string {
	logoOnce.Do(func() {
		if len(LogoPNG) == 0 {
			return
		}
		var targetDir string
		if runtime.GOOS == "windows" {
			progData := os.Getenv("ProgramData")
			if progData == "" {
				progData = `C:\ProgramData`
			}
			targetDir = filepath.Join(progData, "ADSIEM")
		} else {
			targetDir = "/var/lib/adsiem"
		}

		_ = os.MkdirAll(targetDir, 0755)
		target := filepath.Join(targetDir, "logo.png")

		// If writing to system directory fails (e.g. non-root in dev/test), fall back to temp dir
		if err := os.WriteFile(target, LogoPNG, 0644); err != nil {
			target = filepath.Join(os.TempDir(), "adsiem_logo.png")
			_ = os.WriteFile(target, LogoPNG, 0644)
		}
		logoPath = target
	})
	return logoPath
}
