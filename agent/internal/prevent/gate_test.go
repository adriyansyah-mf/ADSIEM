package prevent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/malhash"
	"github.com/siem-platform/agent/internal/policy"
)

// A SHA-256 exclusion applies to a path rule too, which matches without
// reading the file: the hash is computed for the exclusion.
func TestHashExclusionCoversPathRules(t *testing.T) {
	sum := strings.Repeat("aa", 32)
	dir := t.TempDir()
	p, _ := Compile([]Rule{{ID: "d", Name: "dir", RuleType: TypeDir, Value: dir, Action: ActionBlock}})
	hashed := 0
	e := Exec{Path: filepath.Join(dir, "tool"), Hash: func() (string, bool) { hashed++; return sum, true }}
	if p.Match(e, false) == nil || hashed != 0 {
		t.Fatal("no hash exclusion: the path rule matches without hashing")
	}
	gated := p.withGate(false, []policy.Exclusion{{Kind: "sha256", Value: sum, Scopes: []string{policy.ScopePrevention}}})
	if gated.Match(e, false) != nil {
		t.Fatal("the excluded hash must not be stopped by a path rule")
	}
}

func TestGroupPolicyGate(t *testing.T) {
	g := &guard{hashes: map[string]string{}}
	ruleHash, feedHash := strings.Repeat("cd", 32), strings.Repeat("ef", 32)
	base, _ := compileWith([]Rule{{ID: "r1", Name: "mine", RuleType: TypeHash, Value: ruleHash, Action: ActionBlock}}, g)
	p := base.withMalware(malhash.New(malhash.ActionBlock, map[string]string{feedHash: "Emotet"}), "")
	exec := func(path, h string) Exec {
		return Exec{Path: path, Hash: func() (string, bool) { return h, true }}
	}
	if p.withGate(true, nil).Match(exec("/tmp/x", ruleHash), false) != nil || p.withGate(true, nil).active() {
		t.Fatal("prevention off: nothing matches")
	}
	ex := []policy.Exclusion{
		{Kind: "image", Value: "/opt/tools/scanner", Scopes: []string{policy.ScopePrevention}},
		{Kind: "sha256", Value: feedHash, Scopes: []string{policy.ScopeMalware}},
	}
	gated := p.withGate(false, ex)
	if gated.Match(exec("/opt/tools/scanner", ruleHash), false) != nil {
		t.Fatal("an excluded program is not stopped by a rule")
	}
	if gated.Match(exec("/tmp/x", ruleHash), false) == nil {
		t.Fatal("others still are")
	}
	if gated.Match(exec("/tmp/y", feedHash), false) != nil {
		t.Fatal("an excluded hash is not known malware")
	}
	// the prevention scope does not excuse known malware
	other := p.withGate(false, []policy.Exclusion{{Kind: "image", Value: "/tmp/y", Scopes: []string{policy.ScopePrevention}}})
	if c := other.Match(exec("/tmp/y", feedHash), false); c == nil || c.RuleType != TypeKnownMalware {
		t.Fatal("scopes are separate")
	}
}

func TestManagerSetGateEmptiesTheEngines(t *testing.T) {
	eng := &fakeEngines{}
	m := &Manager{eng: eng, last: map[string]time.Time{}}
	m.Apply("h1", []Rule{{Name: "tmp", RuleType: TypeDir, Value: t.TempDir(), Action: ActionBlock}})
	m.SetGate(true, nil)
	last := eng.applied[len(eng.applied)-1]
	if len(last.Rules) != 0 || last.active() {
		t.Fatal("off: the engines (and the BPF LSM) get no rules")
	}
	m.Apply("h2", []Rule{{Name: "tmp", RuleType: TypeDir, Value: t.TempDir(), Action: ActionBlock}})
	if last = eng.applied[len(eng.applied)-1]; len(last.Rules) != 0 {
		t.Fatal("new rules stay off while the policy says off")
	}
	m.SetGate(false, nil)
	if last = eng.applied[len(eng.applied)-1]; len(last.Rules) != 1 {
		t.Fatal("back on: the rules return")
	}
}
