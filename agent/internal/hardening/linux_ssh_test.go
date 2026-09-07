package hardening

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckSSHNoRootLogin(t *testing.T) {
	hardened := writeTemp(t, "sshd_config", "PermitRootLogin no\n")
	if c := checkSSHNoRootLogin(hardened); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unhardened := writeTemp(t, "sshd_config", "PermitRootLogin yes\n")
	if c := checkSSHNoRootLogin(unhardened); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	unset := writeTemp(t, "sshd_config", "Port 22\n")
	if c := checkSSHNoRootLogin(unset); c.Status != StatusFail {
		t.Fatalf("expected fail when unset (OpenSSH default is not 'no'), got %s", c.Status)
	}

	if c := checkSSHNoRootLogin("/nonexistent/sshd_config"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", c.Status)
	}
}

func TestParseSSHDConfig_FollowsIncludeDirective(t *testing.T) {
	base := t.TempDir()
	dropinDir := filepath.Join(base, "conf.d")
	if err := os.MkdirAll(dropinDir, 0755); err != nil {
		t.Fatalf("mkdir conf.d: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dropinDir, "hardening.conf"), []byte("PermitRootLogin no\n"), 0644); err != nil {
		t.Fatalf("write drop-in: %v", err)
	}

	mainPath := filepath.Join(base, "sshd_config")
	mainContent := "Include " + filepath.Join(dropinDir, "*.conf") + "\n"
	if err := os.WriteFile(mainPath, []byte(mainContent), 0644); err != nil {
		t.Fatalf("write main config: %v", err)
	}

	if c := checkSSHNoRootLogin(mainPath); c.Status != StatusPass {
		t.Fatalf("expected pass via Include drop-in, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckSSHNoPasswordAuth(t *testing.T) {
	hardened := writeTemp(t, "sshd_config", "PasswordAuthentication no\n")
	if c := checkSSHNoPasswordAuth(hardened); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unhardened := writeTemp(t, "sshd_config", "PasswordAuthentication yes\n")
	if c := checkSSHNoPasswordAuth(unhardened); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckSSHProtocol2(t *testing.T) {
	explicit := writeTemp(t, "sshd_config", "Protocol 2\n")
	if c := checkSSHProtocol2(explicit); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	omitted := writeTemp(t, "sshd_config", "Port 22\n")
	if c := checkSSHProtocol2(omitted); c.Status != StatusPass {
		t.Fatalf("expected pass when omitted (modern OpenSSH defaults to 2), got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckSSHMaxAuthTries(t *testing.T) {
	good := writeTemp(t, "sshd_config", "MaxAuthTries 4\n")
	if c := checkSSHMaxAuthTries(good); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "sshd_config", "MaxAuthTries 6\n")
	if c := checkSSHMaxAuthTries(bad); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	unset := writeTemp(t, "sshd_config", "Port 22\n")
	if c := checkSSHMaxAuthTries(unset); c.Status != StatusFail {
		t.Fatalf("expected fail when unset (OpenSSH default is 6), got %s", c.Status)
	}
}
