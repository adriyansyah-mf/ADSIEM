//go:build linux

package webblock

import (
	"os"
	"os/exec"
)

func defaultHostsPath() string { return "/etc/hosts" }

func replaceFile(tmp, dst string) error { return os.Rename(tmp, dst) }

// flushDNSCache clears the resolver caches that may hold the old answers.
// Missing tools are ignored.
func flushDNSCache() error {
	var firstErr error
	if p, err := exec.LookPath("resolvectl"); err == nil {
		if exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil {
			if err := exec.Command(p, "flush-caches").Run(); err != nil {
				firstErr = err
			}
		}
	}
	if p, err := exec.LookPath("nscd"); err == nil {
		if err := exec.Command(p, "-i", "hosts").Run(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
