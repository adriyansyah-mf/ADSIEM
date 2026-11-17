package appcontrol

import (
	"errors"
	"strings"
	"testing"
)

func TestSignerSamplesFollowTheirRules(t *testing.T) {
	samples := map[string]string{
		"proton ag":             `C:\Users\a\Downloads\ProtonVPN_v5.exe`,
		"psiphon inc.":          `C:\Users\a\Desktop\psiphon3.exe`,
		"microsoft corporation": `C:\Windows\notepad.exe`,
	}
	rules := [][2]string{{"signer", "Proton AG"}, {"signer", "Microsoft Corporation"}}
	p := NewPlan(ModeEnforce, rules, nil, samples)
	if len(p.Signers) != 1 || p.Signers[0] != samples["proton ag"] {
		t.Fatalf("only Proton's rule is active (and never Microsoft): %v", p.Signers)
	}
	if p.Rules() != 1 {
		t.Fatalf("rules: %d", p.Rules())
	}
	s := ApplyScript(p, `C:\w`)
	if !strings.Contains(s, `New-CIPolicyRule -Deny -Level Publisher -DriverFilePath 'C:\Users\a\Downloads\ProtonVPN_v5.exe'`) {
		t.Fatalf("publisher rule missing:\n%s", s)
	}
	// the rule turned off: the publisher deny goes with it
	if off := NewPlan(ModeEnforce, nil, nil, samples); len(off.Signers) != 0 || off.Key() == p.Key() {
		t.Fatalf("rule off: %+v", off)
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
	// survives a restart
	c2 := &Controller{Dir: c.Dir}
	c2.mu.Lock()
	c2.load()
	c2.mu.Unlock()
	if len(c2.st.Signers) != 2 {
		t.Fatalf("not saved: %v", c2.st.Signers)
	}
}
