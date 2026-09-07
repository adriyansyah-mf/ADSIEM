package hardening

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

func TestCheckPasswordMaxAge(t *testing.T) {
	pass := writeTemp(t, "login.defs", "PASS_MAX_DAYS\t90\n")
	if c := checkPasswordMaxAge(pass); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	fail := writeTemp(t, "login.defs", "PASS_MAX_DAYS\t99999\n")
	if c := checkPasswordMaxAge(fail); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	missing := writeTemp(t, "login.defs", "# no directive here\n")
	if c := checkPasswordMaxAge(missing); c.Status != StatusFail {
		t.Fatalf("expected fail when directive absent, got %s", c.Status)
	}

	if c := checkPasswordMaxAge("/nonexistent/login.defs"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable for missing file, got %s", c.Status)
	}
}

func TestCheckPasswordComplexity(t *testing.T) {
	good := writeTemp(t, "common-password", "password requisite pam_pwquality.so retry=3\n")
	if c := checkPasswordComplexity([]string{good}); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "common-password", "password required pam_unix.so\n")
	if c := checkPasswordComplexity([]string{bad}); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkPasswordComplexity([]string{"/nonexistent/a", "/nonexistent/b"}); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable when no candidate file exists, got %s", c.Status)
	}
}

func TestCheckAccountLockout(t *testing.T) {
	good := writeTemp(t, "common-auth", "auth required pam_faillock.so preauth\n")
	if c := checkAccountLockout([]string{good}); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "common-auth", "auth required pam_unix.so\n")
	if c := checkAccountLockout([]string{bad}); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckNoEmptyPasswords(t *testing.T) {
	good := writeTemp(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nuser:$6$def:19000:0:99999:7:::\n")
	if c := checkNoEmptyPasswords(good); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n")
	c := checkNoEmptyPasswords(bad)
	if c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkNoEmptyPasswords("/nonexistent/shadow"); c.Status != StatusError {
		t.Fatalf("expected error for unreadable shadow file, got %s", c.Status)
	}
}

func TestCheckNoDuplicateRootUID(t *testing.T) {
	good := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n")
	if c := checkNoDuplicateRootUID(good); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/bash\n")
	c := checkNoDuplicateRootUID(bad)
	if c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}
