package sca

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTemp: %v", err)
	}
	return path
}

func writeTempMode(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("writeTempMode: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func mustParse(t *testing.T, raw string) *rule {
	t.Helper()
	r, err := parseRule(raw)
	if err != nil {
		t.Fatalf("parseRule(%q): %v", raw, err)
	}
	return r
}

func TestFileExists(t *testing.T) {
	f := writeTemp(t, "x", "content")
	if e := mustParse(t, "f:"+f).evaluate(); e.status != evalPass {
		t.Fatalf("expected pass, got %v (%s)", e.status, e.detail)
	}
	if e := mustParse(t, "f:/nonexistent/x").evaluate(); e.status != evalFail {
		t.Fatalf("expected fail, got %v", e.status)
	}
	if e := mustParse(t, "not f:/nonexistent/x").evaluate(); e.status != evalPass {
		t.Fatalf("expected pass for negated missing file, got %v", e.status)
	}
	if e := mustParse(t, "not f:"+f).evaluate(); e.status != evalFail {
		t.Fatalf("expected fail for negated existing file, got %v", e.status)
	}
}

func TestFileRegex(t *testing.T) {
	f := writeTemp(t, "x", "PASS_MAX_DAYS\t90\n")
	if e := mustParse(t, "f:"+f+" -> r:PASS_MAX_DAYS").evaluate(); e.status != evalPass {
		t.Fatalf("expected pass, got %v (%s)", e.status, e.detail)
	}
	if e := mustParse(t, "f:"+f+" -> r:NOPE").evaluate(); e.status != evalFail {
		t.Fatalf("expected fail, got %v", e.status)
	}
	if e := mustParse(t, "f:/nonexistent -> r:x").evaluate(); e.status != evalSkip {
		t.Fatalf("expected skip for missing file, got %v", e.status)
	}
}

func TestFileNotRegex(t *testing.T) {
	f := writeTemp(t, "x", "Protocol 1\n")
	if e := mustParse(t, "f:"+f+" -> !r:Protocol 1").evaluate(); e.status != evalFail {
		t.Fatalf("expected fail (regex present), got %v", e.status)
	}
	f2 := writeTemp(t, "y", "Protocol 2\n")
	if e := mustParse(t, "f:"+f2+" -> !r:Protocol 1").evaluate(); e.status != evalPass {
		t.Fatalf("expected pass (regex absent), got %v", e.status)
	}
}

func TestFileNumericCompare(t *testing.T) {
	f := writeTemp(t, "x", "PASS_MAX_DAYS\t90\n")
	if e := mustParse(t, `f:`+f+` -> n:PASS_MAX_DAYS\s+(\d+) compare between 1..90`).evaluate(); e.status != evalPass {
		t.Fatalf("expected pass, got %v (%s)", e.status, e.detail)
	}
	f2 := writeTemp(t, "y", "PASS_MAX_DAYS\t99999\n")
	if e := mustParse(t, `f:`+f2+` -> n:PASS_MAX_DAYS\s+(\d+) compare between 1..90`).evaluate(); e.status != evalFail {
		t.Fatalf("expected fail, got %v", e.status)
	}
	f3 := writeTemp(t, "z", "# no directive here\n")
	if e := mustParse(t, `f:`+f3+` -> n:PASS_MAX_DAYS\s+(\d+) compare between 1..90`).evaluate(); e.status != evalFail {
		t.Fatalf("expected fail when directive absent, got %v", e.status)
	}
}

func TestFilePermission(t *testing.T) {
	good := writeTempMode(t, "shadow", "root:x:::::::\n", 0640)
	if e := mustParse(t, "f:"+good+" -> perm<=0640").evaluate(); e.status != evalPass {
		t.Fatalf("expected pass, got %v (%s)", e.status, e.detail)
	}
	bad := writeTempMode(t, "open", "root:x:::::::\n", 0644)
	if e := mustParse(t, "f:"+bad+" -> perm<=0640").evaluate(); e.status != evalFail {
		t.Fatalf("expected fail for world-readable file, got %v (%s)", e.status, e.detail)
	}
	if e := mustParse(t, "f:/nonexistent -> perm<=0640").evaluate(); e.status != evalSkip {
		t.Fatalf("expected skip, got %v", e.status)
	}
}

func TestFileUnreadableIsFailNotSkip(t *testing.T) {
	// A file that Stat can see but ReadFile can't open (permission denied)
	// must surface as a real failure, not be silently folded into "missing".
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	if err := os.WriteFile(path, []byte("secret"), 0000); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block root reads")
	}
	e := mustParse(t, "f:"+path+" -> r:x").evaluate()
	if e.status != evalFail {
		t.Fatalf("expected fail for unreadable file, got %v (%s)", e.status, e.detail)
	}
}

func TestCommandRegex(t *testing.T) {
	if e := mustParse(t, "c:echo hello -> r:hello").evaluate(); e.status != evalPass {
		t.Fatalf("expected pass, got %v (%s)", e.status, e.detail)
	}
	if e := mustParse(t, "c:echo hello -> r:goodbye").evaluate(); e.status != evalFail {
		t.Fatalf("expected fail, got %v", e.status)
	}
	if e := mustParse(t, "c:this-binary-does-not-exist-xyz -> r:x").evaluate(); e.status != evalSkip {
		t.Fatalf("expected skip for missing binary, got %v", e.status)
	}
}

func TestMountOpts(t *testing.T) {
	if e := mustParse(t, "m:/definitely-not-a-real-mountpoint-xyz -> opts:noexec,nosuid").evaluate(); e.status != evalSkip {
		t.Fatalf("expected skip for a mountpoint that doesn't exist, got %v", e.status)
	}
}

func TestParseRuleErrors(t *testing.T) {
	cases := []string{
		"badselector:/x",
		"f:/x -> r:(unterminated",
		"f:/x -> n:missing-compare-clause",
		"f:/x -> perm<=notoctal",
	}
	for _, c := range cases {
		if _, err := parseRule(c); err == nil {
			t.Errorf("expected parse error for %q", c)
		}
	}
}
