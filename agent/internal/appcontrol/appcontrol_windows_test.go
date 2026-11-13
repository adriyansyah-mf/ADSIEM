//go:build windows

package appcontrol

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// longPath expands 8.3 components (C:\Users\RUNNER~1\...): App Control
// matches FilePath rules against the long path.
func longPath(t *testing.T, p string) string {
	in, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		t.Fatalf("GetLongPathName(%s): %v", p, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// diagnose logs what Windows thinks is active and what CodeIntegrity logged.
func diagnose(t *testing.T) {
	script := `$ProgressPreference = 'SilentlyContinue'
$ci = Get-Command CiTool.exe -ErrorAction SilentlyContinue
if ($ci) { & $ci.Source --list-policies -json | ConvertFrom-Json | Select-Object -ExpandProperty Policies |
  Where-Object { $_.FriendlyName -like 'SIEM*' } | Format-List | Out-String }
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 8 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message | Format-List | Out-String -Width 300`
	out, err := PowerShell()(context.Background(), script)
	t.Logf("diagnostics (err=%v):\n%s", err, out)
}

// On a real elevated Windows host (APPCONTROL_E2E=1): an enforce policy with
// a path rule stops a copied program before it runs; removing the policy
// lets it run again (CiTool) or schedules the removal for the next boot.
func TestAppControlEnforcesAPathRule(t *testing.T) {
	if os.Getenv("APPCONTROL_E2E") != "1" {
		t.Skip("set APPCONTROL_E2E=1 on a disposable Windows host")
	}
	dir := longPath(t, t.TempDir())
	exe := filepath.Join(dir, "siem-appcontrol-test.exe")
	src, err := os.Open(filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe"))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.Create(exe)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(dst, src)
	src.Close()
	dst.Close()
	if err := exec.Command(exe).Run(); err != nil {
		t.Fatalf("the copy must run before the policy: %v", err)
	}

	c := &Controller{Dir: filepath.Join(dir, "state"), Run: PowerShell(), In: Inputs{
		Mode:  func() string { return ModeEnforce },
		Rules: func() [][2]string { return [][2]string{{"path", exe}} },
	}}
	t.Cleanup(func() {
		c.In.Mode = func() string { return ModeOff }
		c.Reconcile(context.Background())
		t.Logf("removal: %+v", c.Health())
		if h := c.Health(); h.Error != "" || (h.Method != "citool" && h.Method != "reboot") {
			t.Errorf("removal must report citool or reboot: %+v", h)
		}
	})
	c.Reconcile(context.Background())
	h := c.Health()
	if h.Error != "" {
		t.Fatalf("apply: %s", h.Error)
	}
	if h.Method != "citool" && h.Method != "cim" {
		t.Fatalf("apply must report its method, got %q", h.Method)
	}
	t.Logf("applied: %+v (rule %s)", h, exe)
	if err := exec.Command(exe).Run(); err == nil {
		diagnose(t)
		t.Fatal("App Control enforce must stop the program before it runs")
	} else {
		t.Logf("blocked as expected: %v", err)
	}
}
