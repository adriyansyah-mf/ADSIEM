//go:build windows

package appcontrol

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// signedThirdParty finds a program on the host signed by a publisher other
// than Microsoft (a browser on the GitHub Windows runner image).
func signedThirdParty(t *testing.T) (string, string) {
	pf := os.Getenv("ProgramFiles")
	for _, p := range []string{
		filepath.Join(pf, "Mozilla Firefox", "firefox.exe"),
		filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(pf, "Git", "cmd", "git.exe"),
	} {
		if pub, err := readSigner(p); err == nil && pub != "" {
			return p, pub
		}
	}
	t.Skip("no program signed by a third party on this host")
	return "", ""
}

// On a real elevated Windows host (APPCONTROL_E2E=1): a signer block rule
// whose publisher was learned from a stopped program becomes a WDAC
// publisher deny: a copy of another program from that publisher, in a
// folder no path rule names, cannot start.
func TestAppControlEnforcesAPublisherRule(t *testing.T) {
	if os.Getenv("APPCONTROL_E2E") != "1" {
		t.Skip("set APPCONTROL_E2E=1 on a disposable Windows host")
	}
	src, publisher := signedThirdParty(t)
	dir := longPath(t, t.TempDir())
	sample := filepath.Join(dir, "sample.exe")
	other := filepath.Join(dir, "elsewhere", "renamed-copy.exe")
	os.MkdirAll(filepath.Dir(other), 0o755)
	for _, dst := range []string{sample, other} {
		in, err := os.Open(src)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.Create(dst)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(out, in)
		in.Close()
		out.Close()
	}
	c := &Controller{Dir: filepath.Join(dir, "state"), Run: PowerShell(), wake: make(chan struct{}, 1), In: Inputs{
		Mode:  func() string { return ModeEnforce },
		Rules: func() [][2]string { return [][2]string{{"signer", publisher}} },
	}}
	t.Logf("sample %s (from %s), publisher %q", sample, src, publisher)
	c.Learn("signer", sample, "") // as the prevention engine does after stopping it
	if c.st.Signers == nil || c.st.Signers[strings.ToLower(publisher)] != sample {
		t.Fatalf("publisher %q not learned: %v", publisher, c.st.Signers)
	}
	// the one ConfigCI call this rule adds, on its own and timed
	probe, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	out, err := PowerShell()(probe, "$ErrorActionPreference = 'Stop'\nImport-Module ConfigCI\n"+
		"$sw = [Diagnostics.Stopwatch]::StartNew()\n"+
		"$r = New-CIPolicyRule -Deny -Level Publisher -DriverFilePath "+psQuote(sample)+"\n"+
		"'rules=' + @($r).Count + ' ms=' + $sw.ElapsedMilliseconds + ' first=' + (@($r)[0] | Out-String).Trim()")
	cancel()
	t.Logf("New-CIPolicyRule -Level Publisher alone: err=%v\n%s", err, out)
	t.Cleanup(func() {
		c.In.Mode = func() string { return ModeOff }
		c.Reconcile(context.Background())
		t.Logf("removal: %+v", c.Health())
	})
	c.Reconcile(context.Background())
	if h := c.Health(); h.Error != "" {
		t.Fatalf("apply: %s", h.Error)
	}
	cmd := exec.Command(other, "--version")
	if err := cmd.Start(); err == nil {
		_ = cmd.Process.Kill()
		diagnose(t)
		t.Fatalf("a program signed by %q must not start under the publisher deny", publisher)
	} else {
		t.Logf("blocked as expected (%s): %v", publisher, err)
	}
}
