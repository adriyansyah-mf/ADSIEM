//go:build windows

package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// upgradeCode is the MSI's UpgradeCode (packaging/windows/siem-agent.wxs).
const upgradeCode = "0F952687-E21C-4316-9931-D9A9C4FE7FA2"

// packedGUID is the form Windows Installer uses for registry key names: the
// first three groups reversed, then each byte of the rest nibble-swapped.
func packedGUID(guid string) string {
	g := strings.ReplaceAll(strings.Trim(guid, "{}"), "-", "")
	rev := func(s string) string {
		b := []byte(s)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return string(b)
	}
	out := rev(g[0:8]) + rev(g[8:12]) + rev(g[12:16])
	for i := 16; i < 32; i += 2 {
		out += string(g[i+1]) + string(g[i])
	}
	return strings.ToUpper(out)
}

// DetectKind: only an MSI install can be upgraded in place (a zip install has
// no installer to run).
func DetectKind() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Classes\Installer\UpgradeCodes\`+packedGUID(upgradeCode), registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", errors.New("agent not installed from the MSI")
	}
	k.Close()
	return "msi", nil
}

// InstallPackage runs msiexec detached: the MSI stops the SIEMAgent service,
// and the installer must outlive this process. Exit 3010 is success with a
// reboot pending (never forced: /norestart).
func InstallPackage(ctx context.Context, kind, pkg, logPath string) error {
	if kind != "msi" {
		return fmt.Errorf("no installer for %q packages", kind)
	}
	msiexec := filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
	cmd := exec.CommandContext(ctx, msiexec, "/i", pkg, "/qn", "/norestart", "/l*v", logPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 3010 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("msiexec: %w (log %s)", err, logPath)
	}
	return nil
}
