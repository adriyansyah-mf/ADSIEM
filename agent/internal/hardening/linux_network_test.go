package hardening

import "testing"

func TestCheckIPForwardDisabled(t *testing.T) {
	disabled := writeTemp(t, "ip_forward", "0\n")
	if c := checkIPForwardDisabled(disabled); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	enabled := writeTemp(t, "ip_forward", "1\n")
	if c := checkIPForwardDisabled(enabled); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkIPForwardDisabled("/nonexistent/ip_forward"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", c.Status)
	}
}

func TestCheckNoLegacyServices(t *testing.T) {
	clean := []PortInfo{{Port: 443, Proto: "tcp", State: "listen"}, {Port: 22, Proto: "tcp", State: "listen"}}
	if c := checkNoLegacyServices(clean); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	withTelnet := []PortInfo{{Port: 23, Proto: "tcp", State: "listen"}, {Port: 443, Proto: "tcp", State: "listen"}}
	c := checkNoLegacyServices(withTelnet)
	if c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	notListening := []PortInfo{{Port: 23, Proto: "tcp", State: "closed"}}
	if c := checkNoLegacyServices(notListening); c.Status != StatusPass {
		t.Fatalf("expected pass for a non-listening legacy port, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckFirewallActive_ReturnsValidStatus(t *testing.T) {
	// checkFirewallActive shells out to real system firewall tools, so this
	// is a smoke test (valid shape), not a deterministic pass/fail test —
	// mocking exec.Command would need infrastructure this repo doesn't have.
	c := checkFirewallActive()
	switch c.Status {
	case StatusPass, StatusFail, StatusNotApplicable, StatusError:
	default:
		t.Fatalf("unexpected status: %q", c.Status)
	}
	if c.ID != "net-firewall-active" {
		t.Fatalf("unexpected ID: %q", c.ID)
	}
}
