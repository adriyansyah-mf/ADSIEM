package prevent

import (
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/policy"
)

func signerOf(name string) func() (string, bool) {
	return func() (string, bool) { return name, true }
}

func TestSignerRulesMatchThePublisherAnyCase(t *testing.T) {
	p, errs := Compile([]Rule{
		{ID: "s1", Name: "no NordVPN", RuleType: TypeSigner, Value: " nordvpn s.a. ", Action: ActionBlock},
		{ID: "s2", Name: "watch Tor Browser", RuleType: TypeSigner, Value: "THE TOR PROJECT, INC.", Action: ActionDetect},
		{ID: "s3", Name: "empty", RuleType: TypeSigner, Value: "  ", Action: ActionBlock},
	})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "publisher") {
		t.Fatalf("errs: %v", errs)
	}
	c := p.Match(Exec{Path: `C:\Users\a\Downloads\NordVPNSetup.exe`, Signer: signerOf("NordVPN S.A.")}, false)
	if c == nil || c.ID != "s1" || !c.block {
		t.Fatalf("match: %+v", c)
	}
	if c := p.Match(Exec{Path: `C:\x\firefox.exe`, Signer: signerOf("The Tor Project, Inc.")}, false); c == nil ||
		c.ID != "s2" || c.block {
		t.Fatalf("detect rule: %+v", c)
	}
	if c := p.Match(Exec{Path: `C:\x\other.exe`, Signer: signerOf("Mozilla Corporation")}, false); c != nil {
		t.Fatalf("other publisher matched %+v", c)
	}
	// no signer reader (Linux, fanotify): signer rules never match
	if c := p.Match(Exec{Path: "/usr/bin/nordvpn"}, false); c != nil {
		t.Fatalf("without a reader: %+v", c)
	}
}

func TestMicrosoftSignerIsNeverBlocked(t *testing.T) {
	p, errs := Compile([]Rule{{ID: "m", Name: "oops", RuleType: TypeSigner, Value: "Microsoft Windows", Action: ActionBlock}})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "Microsoft") {
		t.Fatalf("errs: %v", errs)
	}
	c := p.Match(Exec{Path: `C:\Windows\System32\cmd.exe`, Signer: signerOf("Microsoft Windows")}, false)
	if c == nil || c.block {
		t.Fatalf("kept, but detect only: %+v", c)
	}
}

func TestSignerRuleHonoursExclusions(t *testing.T) {
	p, _ := Compile([]Rule{{ID: "w", Name: "no WireGuard", RuleType: TypeSigner, Value: "WireGuard LLC", Action: ActionBlock}})
	g := p.withGate(false, []policy.Exclusion{{Kind: "path_prefix", Value: `C:\Program Files\WireGuard\`,
		Scopes: []string{policy.ScopePrevention}}})
	if c := g.Match(Exec{Path: `C:\Program Files\WireGuard\wireguard.exe`, Signer: signerOf("WireGuard LLC")}, false); c != nil {
		t.Fatalf("the approved company install is excluded: %+v", c)
	}
	if c := g.Match(Exec{Path: `C:\Users\a\Downloads\wireguard.exe`, Signer: signerOf("WireGuard LLC")}, false); c == nil {
		t.Fatal("a copy elsewhere still matches")
	}
}

func TestSignerDecisionLine(t *testing.T) {
	p, _ := Compile([]Rule{{ID: "s1", Name: "no Psiphon", RuleType: TypeSigner, Value: "Psiphon Inc.", Action: ActionBlock}})
	c := p.Match(Exec{Path: `C:\u\psiphon3.exe`, Signer: signerOf("Psiphon Inc.")}, false)
	line := Decision{Rule: c, Terminated: true, Engine: "etw", Path: `C:\u\psiphon3.exe`, Signer: "Psiphon Inc."}.line()
	for _, want := range []string{"action=terminated", `rule="no Psiphon"`, "rule_type=signer", `Signer="Psiphon Inc."`} {
		if !strings.Contains(line, want) {
			t.Fatalf("line lacks %q: %s", want, line)
		}
	}
}
