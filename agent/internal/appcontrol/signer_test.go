package appcontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSignerFragmentsFollowTheirRules(t *testing.T) {
	ready := map[string]string{
		"proton ag":             `C:\ProgramData\SIEMAgent\appcontrol\publishers\a.xml`,
		"psiphon inc.":          `C:\ProgramData\SIEMAgent\appcontrol\publishers\b.xml`,
		"microsoft corporation": `C:\ProgramData\SIEMAgent\appcontrol\publishers\c.xml`,
	}
	rules := [][2]string{{"signer", "Proton AG"}, {"signer", "Microsoft Corporation"}}
	p := NewPlan(ModeEnforce, rules, nil, ready)
	if len(p.Signers) != 1 || p.Signers[0] != ready["proton ag"] {
		t.Fatalf("only Proton's rule is active (and never Microsoft): %v", p.Signers)
	}
	if p.Rules() != 1 {
		t.Fatalf("rules: %d", p.Rules())
	}
	s := ApplyScript(p, `C:\w`)
	for _, want := range []string{`$policies += 'C:\ProgramData\SIEMAgent\appcontrol\publishers\a.xml'`,
		"Merge-CIPolicy -PolicyPaths $policies -OutputFilePath $merged | Out-Null"} {
		if !strings.Contains(s, want) {
			t.Fatalf("apply script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "-Level Publisher") {
		t.Fatal("the slow publisher rule is built once in a fragment, never on apply")
	}
	if off := NewPlan(ModeEnforce, nil, nil, ready); len(off.Signers) != 0 || off.Key() == p.Key() {
		t.Fatalf("rule off: %+v", off)
	}
}

func TestScriptMarkersAndFragmentScript(t *testing.T) {
	s := ApplyScript(NewPlan(ModeEnforce, [][2]string{{"signer", "Proton AG"}}, nil,
		map[string]string{"proton ag": `C:\f.xml`}), `C:\w`)
	for _, want := range []string{"'step: path and folder rules'", "'step: merge'", "'step: convert'", "'step: activate'"} {
		if !strings.Contains(s, want) {
			t.Fatalf("apply script lacks %q", want)
		}
	}
	f := FragmentScript(`C:\Users\a\O'Brien\vpn.exe`, `C:\state\publishers\x.xml`)
	for _, want := range []string{
		`New-CIPolicyRule -Deny -Level Publisher -DriverFilePath 'C:\Users\a\O''Brien\vpn.exe'`,
		"New-CIPolicy -Rules $r -FilePath $tmp -UserPEs", "Move-Item -LiteralPath $tmp -Destination $out -Force",
		`'step: publisher rule from ' + 'C:\Users\a\O''Brien\vpn.exe'`, "'fragment'",
	} {
		if !strings.Contains(f, want) {
			t.Fatalf("fragment script lacks %q:\n%s", want, f)
		}
	}
	if got := lastStep("step: merge\nstep: publisher rule from C:\\s.exe\n"); got != `publisher rule from C:\s.exe` {
		t.Fatalf("lastStep = %q", got)
	}
	if got := lastStep(""); got != "the start" {
		t.Fatalf("no marker: %q", got)
	}
}

// fakeRunner builds fragments (writes the file a FragmentScript names) and
// applies policies, recording every script.
type fakeRunner struct {
	mu      sync.Mutex
	scripts []string
	fail    bool
}

func (f *fakeRunner) run(_ context.Context, script string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, script)
	if strings.Contains(script, "New-CIPolicy -Rules") {
		if f.fail {
			return "", errors.New("powershell: timed out")
		}
		for _, line := range strings.Split(script, "\n") {
			if strings.HasPrefix(line, "$out = '") {
				p := strings.TrimSuffix(strings.TrimPrefix(line, "$out = '"), "'")
				os.MkdirAll(filepath.Dir(p), 0o755)
				os.WriteFile(p, []byte("<SiPolicy/>"), 0o644)
			}
		}
		return "fragment", nil
	}
	return "citool", nil
}

func (f *fakeRunner) count(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.scripts {
		if strings.Contains(s, substr) {
			n++
		}
	}
	return n
}

func TestPublisherFragmentIsBuiltOnceAndMerged(t *testing.T) {
	orig := readSigner
	defer func() { readSigner = orig }()
	readSigner = func(string) (string, error) { return "Psiphon Inc.", nil }
	run := &fakeRunner{}
	rules := [][2]string{{"signer", "Psiphon Inc."}}
	c := &Controller{Dir: t.TempDir(), Run: run.run, wake: make(chan struct{}, 1),
		In: Inputs{Mode: func() string { return ModeEnforce }, Rules: func() [][2]string { return rules }}}
	c.Learn("signer", `C:\Users\a\Desktop\psiphon3.exe`, "")
	ctx := context.Background()
	c.Reconcile(ctx)
	frag := c.fragmentPath("psiphon inc.")
	if _, err := os.Stat(frag); err != nil {
		t.Fatalf("fragment not kept: %v", err)
	}
	if run.count("New-CIPolicy -Rules") != 1 || run.count("$policies += '"+frag+"'") != 1 {
		t.Fatalf("one build, then an apply merging it: %d scripts", len(run.scripts))
	}
	if h := c.Health(); h.Error != "" || h.Rules != 1 {
		t.Fatalf("health: %+v", h)
	}
	// the next rebuild (another rule changes) merges the kept fragment, no new build
	rules = append(rules, [2]string{"path", `C:\Tools\x.exe`})
	c.Reconcile(ctx)
	if run.count("New-CIPolicy -Rules") != 1 || run.count("$policies += '"+frag+"'") != 2 {
		t.Fatalf("rebuild built the fragment again")
	}
	// the rule turned off: the publisher leaves the policy
	rules = [][2]string{{"path", `C:\Tools\x.exe`}}
	c.Reconcile(ctx)
	last := run.scripts[len(run.scripts)-1]
	if strings.Contains(last, frag) {
		t.Fatal("a publisher whose rule is off must not be merged")
	}
}

func TestFailedFragmentLeavesThePolicyAndRetriesLater(t *testing.T) {
	orig := readSigner
	defer func() { readSigner = orig }()
	readSigner = func(string) (string, error) { return "Mullvad VPN AB", nil }
	run := &fakeRunner{fail: true}
	c := &Controller{Dir: t.TempDir(), Run: run.run, wake: make(chan struct{}, 1), In: Inputs{
		Mode:  func() string { return ModeEnforce },
		Rules: func() [][2]string { return [][2]string{{"signer", "Mullvad VPN AB"}, {"path", `C:\Tools\x.exe`}} },
	}}
	c.Learn("signer", `C:\Users\a\Downloads\mullvad.exe`, "")
	c.Reconcile(context.Background())
	if h := c.Health(); h.Error != "" || h.Rules != 1 {
		t.Fatalf("the path rule still applies while the publisher fragment is missing: %+v", h)
	}
	c.Reconcile(context.Background())
	if run.count("New-CIPolicy -Rules") != 1 {
		t.Fatal("a failed build is not retried every minute")
	}
}

func TestLearnKeepsOneSamplePerPublisher(t *testing.T) {
	orig := readSigner
	defer func() { readSigner = orig }()
	readSigner = func(path string) (string, error) {
		switch {
		case strings.Contains(path, "proton"):
			return "Proton AG", nil
		case strings.Contains(path, "unsigned"):
			return "", errors.New("authenticode: no embedded signature")
		}
		return "Psiphon Inc.", nil
	}
	c := &Controller{Dir: t.TempDir(), wake: make(chan struct{}, 1)}
	c.Learn("signer", `C:\Users\a\Downloads\proton_v1.exe`, "")
	c.Learn("signer", `C:\Users\a\Downloads\proton_v2.exe`, "")
	c.Learn("signer", `C:\Users\a\Desktop\psiphon3.exe`, "")
	c.Learn("signer", `C:\Users\a\Desktop\unsigned.exe`, "")
	c.Learn("signer", "relative.exe", "")
	if len(c.st.Signers) != 2 || c.st.Signers["proton ag"] != `C:\Users\a\Downloads\proton_v2.exe` ||
		c.st.Signers["psiphon inc."] != `C:\Users\a\Desktop\psiphon3.exe` {
		t.Fatalf("signers: %v", c.st.Signers)
	}
	if len(c.st.Learned) != 0 {
		t.Fatalf("a signer match is not a learned hash: %v", c.st.Learned)
	}
	c2 := &Controller{Dir: c.Dir}
	c2.mu.Lock()
	c2.load()
	c2.mu.Unlock()
	if len(c2.st.Signers) != 2 {
		t.Fatalf("not saved: %v", c2.st.Signers)
	}
}
