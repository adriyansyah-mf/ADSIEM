//go:build linux

package notify

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const notifySendTimeout = 10 * time.Second

func notifyArgs(title, message, logo string) []string {
	args := []string{"-a", "ADSIEM Agent", "-u", "critical"}
	if logo != "" {
		args = append(args, "-i", logo)
	}
	return append(args, title, message)
}

var platformShow = func(title, message string) error {
	notifySend, err := exec.LookPath("notify-send")
	if err != nil {
		return nil // headless server without notify-send
	}
	args := notifyArgs(title, message, EnsureLogo())

	// 1. Running inside a desktop session (dev / standalone user run).
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" || os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		ctx, cancel := context.WithTimeout(context.Background(), notifySendTimeout)
		defer cancel()
		return exec.CommandContext(ctx, notifySend, args...).Run()
	}

	// 2. Running as a root daemon: notify every logged-in user's session bus.
	// The session bus only accepts its owner's uid, so notify-send must run
	// as that user, not as root.
	entries, err := os.ReadDir("/run/user")
	if err != nil {
		return nil
	}
	shown := 0
	var lastErr error
	for _, entry := range entries {
		parsed, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || parsed < 1000 || !entry.IsDir() {
			continue
		}
		uid := uint32(parsed)
		runtimeDir := filepath.Join("/run/user", entry.Name())
		busPath := filepath.Join(runtimeDir, "bus")
		if _, err := os.Stat(busPath); err != nil {
			continue
		}
		if err := notifyAs(notifySend, args, uid, runtimeDir, busPath); err != nil {
			slog.Debug("notify linux: session notify failed", "uid", uid, "err", err)
			lastErr = err
			continue
		}
		shown++
	}
	if shown == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

func notifyAs(notifySend string, args []string, uid uint32, runtimeDir, busPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), notifySendTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, notifySend, args...)
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + busPath,
		"XDG_RUNTIME_DIR=" + runtimeDir,
	}
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		env = append(env, "HOME="+u.HomeDir, "USER="+u.Username, "LOGNAME="+u.Username)
	}
	cmd.Env = env

	euid := os.Geteuid()
	if euid == 0 {
		gid := uid
		if fi, err := os.Stat(runtimeDir); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				gid = st.Gid
			}
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
		}
	} else if euid < 0 || uint32(euid) != uid {
		return fmt.Errorf("cannot reach uid %d session bus as uid %d", uid, euid)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
