package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/yara"
)

func TestValidateReportsRulesFingerprintAndErrors(t *testing.T) {
	good := "rule a { strings: $x = \"evil_marker\" condition: $x }\nprivate rule b { condition: true }"
	v, err := validate(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || strings.Join(v.Rules, ",") != "a,b" || v.Fingerprint != Fingerprint(good) || v.EngineVersion != yara.EngineVersion {
		t.Fatalf("good rule: %+v", v)
	}
	bad, _ := validate(strings.NewReader("rule a {\n strings: $x = \"q\"\n condition: $y\n}"))
	if bad.OK || bad.Error == "" || bad.Line == 0 {
		t.Fatalf("an undefined string is a located error: %+v", bad)
	}
	empty, _ := validate(strings.NewReader("// nothing here"))
	if empty.OK || empty.Error != "the text defines no rule" {
		t.Fatalf("no rule: %+v", empty)
	}
	big, _ := validate(strings.NewReader(strings.Repeat("a", maxRuleBytes+5)))
	if big.OK || !strings.Contains(big.Error, "larger than") {
		t.Fatalf("size cap: %+v", big)
	}
}

func TestCapabilitiesNameTheEngine(t *testing.T) {
	c := capabilities()
	if c.Version != yara.EngineVersion || len(c.Modules) == 0 || c.MaxScanBytes != maxScanBytes {
		t.Fatalf("%+v", c)
	}
}

func TestScanMatchesPerFile(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "r.yar")
	if err := os.WriteFile(rule, []byte(`rule m { strings: $x = "evil_marker" condition: $x }`), 0o600); err != nil {
		t.Fatal(err)
	}
	hit, miss := filepath.Join(dir, "hit"), filepath.Join(dir, "miss")
	_ = os.WriteFile(hit, []byte("...evil_marker..."), 0o600)
	_ = os.WriteFile(miss, []byte("benign"), 0o600)
	res, err := scan([]string{"-rules", rule, hit, miss, filepath.Join(dir, "absent")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || len(res.Files) != 3 || res.Files[0].Rules[0] != "m" || len(res.Files[1].Rules) != 0 {
		t.Fatalf("%+v", res)
	}
	if res.Files[2].Error == "" {
		t.Fatal("a missing file is reported per file")
	}
}
