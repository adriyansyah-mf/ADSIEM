//go:build linux

package webblock

import (
	"context"
	"log/slog"
	"os/exec"
	"time"
)

const flushTimeout = 5 * time.Second

func defaultHostsPath() string { return "/etc/hosts" }

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

// flushDNSCache clears the resolver caches that may hold the old answers.
// Missing tools are ignored.
func flushDNSCache() error {
	var firstErr error
	if _, err := exec.LookPath("resolvectl"); err == nil {
		if run("systemctl", "is-active", "--quiet", "systemd-resolved") == nil {
			if err := run("resolvectl", "flush-caches"); err != nil {
				firstErr = err
			}
		}
	}
	if _, err := exec.LookPath("nscd"); err == nil {
		if err := run("nscd", "-i", "hosts"); err != nil {
			slog.Debug("webblock: nscd invalidate failed", "error", err)
		}
	}
	return firstErr
}
