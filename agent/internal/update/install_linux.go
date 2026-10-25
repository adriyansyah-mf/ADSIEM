//go:build linux

package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// DetectKind is the package format this agent was installed from: updates go
// through the same package manager, so its database, the unit file and the
// conffiles stay right.
func DetectKind() (string, error) {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return "", errors.New("systemd-run not found (updates need systemd)")
	}
	if _, err := os.Stat("/var/lib/dpkg/info/siem-agent.list"); err == nil {
		if _, err := exec.LookPath("dpkg"); err == nil {
			return "deb", nil
		}
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, "rpm", "-q", "--quiet", "siem-agent").Run() == nil {
			return "rpm", nil
		}
	}
	return "", errors.New("agent not installed from the deb or rpm package")
}

// installArgv is the package manager command. dpkg keeps the agent's edited
// config.yaml (its token) without asking; rpm already does (%config(noreplace)).
// Both accept a lower version: rolling a rollout back is a downgrade.
func installArgv(kind, pkg string) ([]string, error) {
	switch kind {
	case "deb":
		return []string{"dpkg", "--force-confold", "--force-confdef", "-i", pkg}, nil
	case "rpm":
		return []string{"rpm", "-U", "--oldpackage", "--replacepkgs", pkg}, nil
	}
	return nil, fmt.Errorf("no installer for %q packages", kind)
}

// systemdRunArgv runs argv in a transient unit: the package scripts stop
// siem-agent.service, which kills everything in its cgroup, so the installer
// must not be our child. --wait reports its exit status while we are alive;
// once we are stopped, the new process reads the result from the state file.
func systemdRunArgv(argv []string, logPath string, now time.Time) []string {
	return append([]string{"systemd-run",
		"--unit=siem-agent-update-" + strconv.FormatInt(now.Unix(), 10),
		"--collect", "--wait", "--quiet",
		"--setenv=DEBIAN_FRONTEND=noninteractive",
		"/bin/sh", "-c", `log=$1; shift; exec "$@" >"$log" 2>&1`, "sh", logPath}, argv...)
}

// InstallPackage is the Install for this platform.
func InstallPackage(ctx context.Context, kind, pkg, logPath string) error {
	argv, err := installArgv(kind, pkg)
	if err != nil {
		return err
	}
	full := systemdRunArgv(argv, logPath, time.Now())
	out, err := exec.CommandContext(ctx, full[0], full[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v %s", argv[0], err, out)
	}
	return nil
}
