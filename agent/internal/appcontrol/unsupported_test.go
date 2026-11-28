package appcontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Windows Home has no ConfigCI: every apply failed at Import-Module and was
// retried every 30 minutes, each run an encoded SYSTEM PowerShell alert.
func TestUnsupportedHostRunsNoScript(t *testing.T) {
	mode := ModeAudit
	unsupported := errors.New("App Control needs Windows Pro, Enterprise or Education")
	run := &fakeRun{out: "citool"}
	var events []string
	c := &Controller{Dir: t.TempDir(), Run: run.run, Supported: func() error { return unsupported },
		In: Inputs{Mode: func() string { return mode },
			Rules: func() [][2]string { return [][2]string{{"path", `C:\x\evil.exe`}} }},
		Push: func(_, line string) { events = append(events, line) }}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		c.Reconcile(ctx)
	}
	if len(run.scripts) != 0 {
		t.Fatalf("unsupported host ran %d scripts", len(run.scripts))
	}
	if h := c.Health(); h.Error != unsupported.Error() || h.Mode != ModeAudit || len(events) != 1 ||
		!strings.Contains(events[0], "app_control_failed") {
		t.Fatalf("health %+v events %v", h, events)
	}
	mode = ModeEnforce
	c.Reconcile(ctx)
	c.Reconcile(ctx)
	if len(run.scripts) != 0 || len(events) != 2 {
		t.Fatalf("a mode change is reported once: scripts %d events %d", len(run.scripts), len(events))
	}
	mode = ModeOff
	c.Reconcile(ctx)
	if len(run.scripts) != 0 {
		t.Fatal("nothing was applied, so nothing is removed")
	}
	// the edition was upgraded: the policy is applied
	mode, c.Supported = ModeAudit, func() error { return nil }
	c.Reconcile(ctx)
	if n := len(run.scripts); n != 1 || !strings.Contains(run.scripts[0], "Import-Module ConfigCI") {
		t.Fatalf("supported host not applied: %d scripts", n)
	}
}

func TestFailedPlanBacksOff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 30 * time.Minute, 2: time.Hour, 3: 2 * time.Hour, 6: 16 * time.Hour,
		7: 24 * time.Hour, 50: 24 * time.Hour} {
		if got := retryAfter(n); got != want {
			t.Fatalf("retryAfter(%d) = %v, want %v", n, got, want)
		}
	}
	run := &fakeRun{err: errors.New("exit status 1")}
	rules := [][2]string{{"path", `C:\x\evil.exe`}}
	c := &Controller{Dir: t.TempDir(), Run: run.run,
		In: Inputs{Mode: func() string { return ModeAudit }, Rules: func() [][2]string { return rules }}}
	ctx := context.Background()
	c.Reconcile(ctx) // fails once
	c.triedAt = time.Now().Add(-retryFailed)
	c.Reconcile(ctx) // retried after 30 min, fails twice
	c.triedAt = time.Now().Add(-retryFailed)
	c.Reconcile(ctx) // the second wait is an hour
	if len(run.scripts) != 2 {
		t.Fatalf("second retry came before an hour: %d scripts", len(run.scripts))
	}
	c.triedAt = time.Now().Add(-time.Hour)
	c.Reconcile(ctx)
	if len(run.scripts) != 3 {
		t.Fatalf("not retried after an hour: %d scripts", len(run.scripts))
	}
	rules = [][2]string{{"path", `C:\x\other.exe`}}
	c.Reconcile(ctx)
	if len(run.scripts) != 4 {
		t.Fatal("a new plan is tried at once")
	}
}

func TestSupportedIn(t *testing.T) {
	win := t.TempDir()
	if err := supportedIn(win); err == nil || !strings.Contains(err.Error(), "ConfigCI") {
		t.Fatalf("Home layout: %v", err)
	}
	mod := filepath.Join(win, `System32\WindowsPowerShell\v1.0\Modules\ConfigCI`)
	pol := filepath.Join(win, `schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml`)
	if err := os.MkdirAll(mod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := supportedIn(win); err == nil || !strings.Contains(err.Error(), "AllowAll.xml") {
		t.Fatalf("no example policy: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(pol), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pol, []byte("<SiPolicy/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := supportedIn(win); err != nil {
		t.Fatalf("Pro layout: %v", err)
	}
}

func TestPSErrorReadsCLIXML(t *testing.T) {
	stderr := "#< CLIXML\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">" +
		"<Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T></TN></Obj>" +
		"<S S=\"Error\">Import-Module : The specified module 'ConfigCI' was not loaded because no valid module file " +
		"was found in any module directory._x000D__x000A_</S><S S=\"Error\">At line:3 char:1_x000D__x000A_</S>" +
		"<S S=\"Error\">+ Import-Module ConfigCI &amp; more_x000D__x000A_</S></Objs>"
	if got := psError(stderr); !strings.HasPrefix(got, "Import-Module : The specified module 'ConfigCI' was not loaded") {
		t.Fatalf("psError = %q", got)
	}
	if got := psError("plain text error"); got != "" {
		t.Fatalf("no CLIXML: %q", got)
	}
}
