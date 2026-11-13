package appcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNewPlanKeepsWindowsPathsOnly(t *testing.T) {
	p := NewPlan(ModeEnforce, [][2]string{
		{"path", `C:\Users\Public\evil.exe`}, {"path", `c:\users\public\EVIL.exe`}, // duplicate, any case
		{"dir", `C:\Temp\drop\`}, {"path", "/tmp/miner"}, {"hash", strings.Repeat("a", 64)},
		{"path", "C:\\bad\npath.exe"},
	}, []string{`C:\Users\a\Downloads\mal.exe`, "relative.exe"})
	if len(p.Paths) != 1 || p.Paths[0] != `C:\Users\Public\evil.exe` {
		t.Fatalf("paths: %v", p.Paths)
	}
	if len(p.Dirs) != 1 || p.Dirs[0] != `C:\Temp\drop` || len(p.Learned) != 1 || p.Rules() != 3 {
		t.Fatalf("plan: %+v", p)
	}
	if p.Key() == NewPlan(ModeAudit, [][2]string{{"path", `C:\Users\Public\evil.exe`}, {"dir", `C:\Temp\drop`}},
		[]string{`C:\Users\a\Downloads\mal.exe`}).Key() {
		t.Fatal("a mode change must change the key")
	}
}

func TestApplyScriptContent(t *testing.T) {
	p := NewPlan(ModeEnforce, [][2]string{{"path", `C:\O'Brien\x.exe`}, {"dir", `C:\Temp\drop`}},
		[]string{`C:\Users\a\mal.exe`})
	s := ApplyScript(p, `C:\ProgramData\SIEMAgent\appcontrol`)
	for _, want := range []string{
		`New-CIPolicyRule -Deny -FilePathRule 'C:\O''Brien\x.exe'`,
		`New-CIPolicyRule -Deny -FilePathRule 'C:\Temp\drop\*'`,
		`New-CIPolicyRule -Deny -Level Hash -DriverFilePath 'C:\Users\a\mal.exe'`,
		`ExamplePolicies\AllowAll.xml`, `Set-RuleOption -FilePath $xml -Option 3 -Delete`,
		"--update-policy", "PS_UpdateAndCompareCIPolicy", PolicyID,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	audit := ApplyScript(NewPlan(ModeAudit, nil, nil), `C:\x`)
	if strings.Contains(audit, "-Option 3 -Delete") || !strings.Contains(audit, "Set-RuleOption -FilePath $xml -Option 3\n") {
		t.Fatal("audit keeps option 3 (Enabled:Audit Mode)")
	}
}

// The scripts must parse; checked with PowerShell's own parser where pwsh exists.
func TestScriptsParse(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed")
	}
	for name, script := range map[string]string{
		"apply": ApplyScript(NewPlan(ModeEnforce, [][2]string{{"path", `C:\a b\x.exe`}, {"dir", `C:\d`}},
			[]string{`C:\l.exe`}), `C:\w`),
		"remove": RemoveScript(),
	} {
		check := `$e = $null; $src = $input | Out-String; [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$e) | Out-Null; if ($e) { $e | ForEach-Object { $_.Message }; exit 1 }`
		cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", check)
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s script does not parse: %v\n%s\n%s", name, err, out, script)
		}
	}
}

func TestEncodedCommandIsUTF16LE(t *testing.T) {
	if encode("ab") != "YQBiAA==" {
		t.Fatal(encode("ab"))
	}
}

type fakeRun struct {
	scripts []string
	out     string
	err     error
}

func (f *fakeRun) run(_ context.Context, s string) (string, error) {
	f.scripts = append(f.scripts, s)
	return f.out, f.err
}

func TestControllerAppliesOnlyChangesAndLearns(t *testing.T) {
	dir := t.TempDir()
	mode := ModeAudit
	rules := [][2]string{{"path", `C:\Users\Public\evil.exe`}}
	run := &fakeRun{out: "citool"}
	var events []map[string]any
	c := &Controller{Dir: dir, Run: run.run, In: Inputs{Mode: func() string { return mode }, Rules: func() [][2]string { return rules }},
		Push: func(lt, line string) {
			var m map[string]any
			_ = json.Unmarshal([]byte(line), &m)
			events = append(events, m)
		}}
	ctx := context.Background()
	c.Reconcile(ctx)
	c.Reconcile(ctx)
	if len(run.scripts) != 1 || !strings.Contains(run.scripts[0], "-Option 3\n") {
		t.Fatalf("one apply in audit mode, got %d", len(run.scripts))
	}
	if h := c.Health(); h.Mode != ModeAudit || h.Method != "citool" || h.Rules != 1 || events[0]["event"] != "app_control_applied" {
		t.Fatalf("health %+v events %v", h, events)
	}

	// a file stopped by a hash rule is learned; path rules are not
	c.Learn("path", `C:\Users\Public\evil.exe`, "")
	c.Learn("hash", `C:\Users\a\mal.exe`, strings.Repeat("b", 64))
	c.Learn("hash", "/usr/bin/x", "")
	c.Reconcile(ctx)
	if len(run.scripts) != 2 || !strings.Contains(run.scripts[1], `-DriverFilePath 'C:\Users\a\mal.exe'`) {
		t.Fatalf("learned file not in the new policy: %d scripts", len(run.scripts))
	}

	// a restarted agent remembers what is applied and learned
	c2 := &Controller{Dir: dir, Run: run.run, In: c.In}
	c2.Reconcile(ctx)
	if len(run.scripts) != 2 {
		t.Fatal("an unchanged plan must not be applied again after a restart")
	}

	// failure: reported, not retried within retryFailed, retried after
	mode, run.err = ModeEnforce, errors.New("ConfigCI module not found")
	c.Reconcile(ctx)
	c.Reconcile(ctx)
	if len(run.scripts) != 3 || c.Health().Error == "" || events[len(events)-1]["event"] != "app_control_failed" {
		t.Fatalf("failure: scripts %d health %+v", len(run.scripts), c.Health())
	}
	c.triedAt = time.Now().Add(-retryFailed)
	run.err = nil
	c.Reconcile(ctx)
	if len(run.scripts) != 4 || !strings.Contains(run.scripts[3], "-Option 3 -Delete") || c.Health().Error != "" {
		t.Fatal("the failed plan is retried later, in enforce mode")
	}

	// off removes the policy
	mode, run.out = ModeOff, "reboot"
	c.Reconcile(ctx)
	if len(run.scripts) != 5 || !strings.Contains(run.scripts[4], "--remove-policy") ||
		events[len(events)-1]["event"] != "app_control_removed" || c.Health().Method != "reboot" {
		t.Fatalf("off: %+v", c.Health())
	}
	c.Reconcile(ctx)
	if len(run.scripts) != 5 {
		t.Fatal("nothing to do once removed")
	}
	if _, err := os.Stat(c.statePath()); err != nil {
		t.Fatal(err)
	}
}

func TestControllerWithoutRunnerOnlyReports(t *testing.T) {
	c := &Controller{Dir: t.TempDir(), In: Inputs{Mode: func() string { return ModeEnforce }}}
	c.Reconcile(context.Background())
	if h := c.Health(); h.Error == "" || h.Mode != ModeEnforce {
		t.Fatalf("health %+v", h)
	}
}
