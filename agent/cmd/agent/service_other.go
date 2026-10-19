//go:build !windows

package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

func defaultConfigPath() string { return "config.yaml" }

// runAsService: outside Windows the agent runs under systemd as a plain process.
func runAsService(func(stop <-chan struct{})) bool { return false }

func manageService(bool, string) error {
	return errors.New("-install/-uninstall are for Windows; on Linux use the siem-agent systemd unit from the .deb/.rpm")
}

// protectService: the Linux unit restarts the agent if it is killed
// (Restart=always); stopping it is reported to the server and alerted on.
func protectService(bool) error { return nil }

// signalStopReason tells a host going down (systemd is "stopping") from
// someone stopping or killing the agent.
func signalStopReason() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "is-system-running").Output()
	if strings.TrimSpace(string(out)) == "stopping" {
		return "system_shutdown"
	}
	return "service_stop"
}
