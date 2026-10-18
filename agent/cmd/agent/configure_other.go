//go:build !windows

package main

import (
	"errors"
	"os"

	"github.com/siem-platform/agent/internal/config"
)

func defaultLogSources() []config.LogSource {
	auth, sys := "/var/log/auth.log", "/var/log/syslog"
	if _, err := os.Stat(auth); err != nil {
		if _, err := os.Stat("/var/log/secure"); err == nil { // RHEL family
			auth, sys = "/var/log/secure", "/var/log/messages"
		}
	}
	return []config.LogSource{
		{Path: auth, Type: "linux_auth", Enabled: true},
		{Path: sys, Type: "syslog", Enabled: true},
	}
}

// The config holds the agent token.
func restrictConfigAccess(path string) error { return os.Chmod(path, 0o600) }

func enableAuditing() error {
	return errors.New("-enable-auditing is only for Windows; on Linux configure auditd")
}
