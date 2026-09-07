package hardening

import "testing"

func TestCheckKernelASLR(t *testing.T) {
	full := writeTemp(t, "randomize_va_space", "2\n")
	if c := checkKernelASLR(full); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	off := writeTemp(t, "randomize_va_space", "0\n")
	if c := checkKernelASLR(off); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckKernelPtraceScope(t *testing.T) {
	restricted := writeTemp(t, "ptrace_scope", "1\n")
	if c := checkKernelPtraceScope(restricted); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unrestricted := writeTemp(t, "ptrace_scope", "0\n")
	if c := checkKernelPtraceScope(unrestricted); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkKernelPtraceScope("/nonexistent/ptrace_scope"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable when Yama LSM absent, got %s", c.Status)
	}
}

func TestCheckKernelCoreDumpRestricted(t *testing.T) {
	restricted := writeTemp(t, "suid_dumpable", "0\n")
	if c := checkKernelCoreDumpRestricted(restricted); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unrestricted := writeTemp(t, "suid_dumpable", "1\n")
	if c := checkKernelCoreDumpRestricted(unrestricted); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckTmpNoExec(t *testing.T) {
	hardened := writeTemp(t, "mounts", "tmpfs /tmp tmpfs rw,noexec,nosuid,nodev 0 0\n")
	if c := checkTmpNoExec(hardened); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unhardened := writeTemp(t, "mounts", "tmpfs /tmp tmpfs rw,relatime 0 0\n")
	if c := checkTmpNoExec(unhardened); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	notSeparate := writeTemp(t, "mounts", "/dev/sda1 / ext4 rw,relatime 0 0\n")
	if c := checkTmpNoExec(notSeparate); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable when /tmp isn't its own mount, got %s", c.Status)
	}
}
