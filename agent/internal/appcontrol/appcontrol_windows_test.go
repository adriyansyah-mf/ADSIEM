//go:build windows

package appcontrol

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// On a real elevated Windows host (APPCONTROL_E2E=1): an enforce policy with
// a path rule stops a copied program before it runs; removing the policy
// lets it run again (CiTool) or schedules the removal for the next boot.
func TestAppControlEnforcesAPathRule(t *testing.T) {
	if os.Getenv("APPCONTROL_E2E") != "1" {
		t.Skip("set APPCONTROL_E2E=1 on a disposable Windows host")
	}
	dir := t.TempDir()
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

	run := PowerShell()
	c := &Controller{Dir: filepath.Join(dir, "state"), Run: run, In: Inputs{
		Mode:  func() string { return ModeEnforce },
		Rules: func() [][2]string { return [][2]string{{"path", exe}} },
	}}
	t.Cleanup(func() {
		c.In.Mode = func() string { return ModeOff }
		c.Reconcile(context.Background())
		t.Logf("removal: %+v", c.Health())
	})
	c.Reconcile(context.Background())
	if h := c.Health(); h.Error != "" {
		t.Fatalf("apply: %s", h.Error)
	}
	t.Logf("applied: %+v", c.Health())
	if err := exec.Command(exe).Run(); err == nil {
		t.Fatal("App Control enforce must stop the program before it runs")
	} else {
		t.Logf("blocked as expected: %v", err)
	}
}
