//go:build linux

package notify

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

var platformShow = func(title, message string) error {
	notifySend, err := exec.LookPath("notify-send")
	if err != nil {
		// Headless server without notify-send installed
		return nil
	}

	logo := EnsureLogo()

	// 1. Direct interactive session (dev / standalone / desktop user)
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" || os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		args := []string{"-a", "ADSIEM Agent", "-u", "critical"}
		if logo != "" {
			args = append(args, "-i", logo)
		}
		args = append(args, title, message)
		return exec.Command(notifySend, args...).Run()
	}

	// 2. Running as daemon / root: notify all active user desktop sessions in /run/user/<uid>
	entries, err := os.ReadDir("/run/user")
	if err != nil {
		return nil
	}

	shown := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		uid, err := strconv.Atoi(entry.Name())
		if err != nil || uid < 1000 {
			continue
		}
		busPath := filepath.Join("/run/user", entry.Name(), "bus")
		if _, err := os.Stat(busPath); err != nil {
			continue
		}

		dbusAddr := fmt.Sprintf("unix:path=%s", busPath)
		args := []string{"-a", "ADSIEM Agent", "-u", "critical"}
		if logo != "" {
			args = append(args, "-i", logo)
		}
		args = append(args, title, message)

		cmd := exec.Command(notifySend, args...)
		cmd.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS="+dbusAddr)
		if err := cmd.Run(); err != nil {
			slog.Debug("notify linux: session notify failed", "uid", uid, "err", err)
		} else {
			shown++
		}
	}

	if shown > 0 {
		return nil
	}
	return nil
}
