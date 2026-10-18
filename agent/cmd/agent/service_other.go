//go:build !windows

package main

import "errors"

func defaultConfigPath() string { return "config.yaml" }

// runAsService: outside Windows the agent runs under systemd as a plain process.
func runAsService(func(stop <-chan struct{})) bool { return false }

func manageService(bool, string) error {
	return errors.New("-install/-uninstall are for Windows; on Linux use the siem-agent systemd unit from the .deb/.rpm")
}
