package hardening

import "testing"

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
