package detect

import (
	"regexp"
	"testing"
	"time"
)

// Uses the exact line shape sshd writes on this host, copied from a real
// /var/log/auth.log: timestamped syslog, bracketed pid, no key=value pairs.
func TestRealSshdLineFromLab(t *testing.T) {
	line := `2026-10-18T14:01:35.584846+00:00 agent-demo sshd-session[456]: Failed password for root from 172.20.0.13 port 41042 ssh2`

	rules, err := ApplyEnabled(DefaultRules(), []string{"ssh_bruteforce"})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	c := &clock{t: time.Unix(1000, 0)}
	blk := newFakeBlocker()
	e := newEngineWith(rules, blk, c)

	group, ok := rules[0].matches("linux_auth", line)
	if !ok {
		t.Fatalf("rule did not match real sshd line; match=%v", rules[0].Match)
	}
	if group != "172.20.0.13" {
		t.Fatalf("group=%q, want 172.20.0.13", group)
	}

	var dets []Detection
	for i := 0; i < 5; i++ {
		dets = e.Observe("linux_auth", line)
	}
	if len(dets) != 1 {
		t.Fatalf("expected one detection after 5 failures, got %d", len(dets))
	}
	if !dets[0].Blocked {
		t.Fatalf("expected a block, got err=%q", dets[0].BlockedErr)
	}
	if blk.blocked["172.20.0.13"] == 0 {
		t.Fatalf("blocked set=%v", blk.blocked)
	}
}

func TestDefaultRulePatternsMatchTheirRealFormats(t *testing.T) {
	cases := []struct {
		rule    string
		logType string
		line    string
		group   string
	}{
		{
			"ssh_bruteforce", "linux_auth",
			`2026-10-18T14:01:35+00:00 host sshd-session[1]: Failed password for invalid user ghost from 203.0.113.7 port 5 ssh2`,
			"203.0.113.7",
		},
		{
			"port_scan", "linux_network_accept",
			`ts=2026-10-18T14:00:00Z pid=1 comm=sshd action=network_accept proto=tcp direction=inbound src=172.20.0.9 dport=22 dst=172.20.0.10 lport=22 host= private_dst=true`,
			"172.20.0.10",
		},
		{
			"webshell_upload", "apache_access",
			`203.0.113.77 - - [18/Oct/2026:14:00:00 +0000] "GET /uploads/cmd.php HTTP/1.1" 200 12 "-" "curl/8"`,
			"203.0.113.77",
		},
	}

	rules, err := ApplyEnabled(DefaultRules(), []string{"ssh_bruteforce", "port_scan", "webshell_upload"})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	byKey := map[string]Rule{}
	for _, r := range rules {
		byKey[r.Key] = r
	}

	for _, c := range cases {
		r, ok := byKey[c.rule]
		if !ok {
			t.Fatalf("rule %s missing", c.rule)
		}
		got, matched := r.matches(c.logType, c.line)
		if !matched {
			t.Errorf("%s did not match its own real-format line: %s", c.rule, c.line)
			continue
		}
		if got != c.group {
			t.Errorf("%s grouped as %q, want %q", c.rule, got, c.group)
		}
	}
}

func TestWebshellPatternIgnoresPlainPhpTraffic(t *testing.T) {
	rules, _ := ApplyEnabled(DefaultRules(), []string{"webshell_upload"})
	rule := rules[2]

	for _, line := range []string{
		`203.0.113.1 - - [18/Oct/2026:14:00:00 +0000] "GET /index.php HTTP/1.1" 200 12 "-" "curl/8"`,
		`203.0.113.1 - - [18/Oct/2026:14:00:00 +0000] "GET /about.php HTTP/1.1" 200 12 "-" "curl/8"`,
	} {
		if _, matched := rule.matches("apache_access", line); matched {
			t.Errorf("ordinary php request must not match: %s", line)
		}
	}
}

func TestSSHRuleMatchesVariants(t *testing.T) {
	rules, _ := ApplyEnabled(DefaultRules(), []string{"ssh_bruteforce"})
	for _, line := range []string{
		`x sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2`,
		`x sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 1 ssh2`,
		`x sshd[1]: Failed none for invalid user ghost from 1.2.3.4 port 1 ssh2`,
		`x sshd[1]: Invalid user oracle from 1.2.3.4 port 1`,
	} {
		if !rules[0].Match.MatchString(line) {
			t.Errorf("should match: %s", line)
		}
		// Sshd writes "Connection closed" for every attempt; it must not count.
	}
	if rules[0].Match.MatchString(`x sshd[1]: Connection closed by authenticating user root 1.2.3.4 port 1 [preauth]`) {
		t.Error("connection-closed lines must not count toward brute force")
	}
}

func TestGroupExprCompilesForAllDefaults(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.GroupExpr != nil && r.GroupExpr.NumSubexp() < 1 {
			t.Errorf("%s: group expression must capture one group", r.Key)
		}
		if r.GroupExpr == nil && r.GroupBy == "" {
			t.Errorf("%s: neither group_by nor group_expr set", r.Key)
		}
	}
}

func TestExtractHandlesQuotedValues(t *testing.T) {
	f := extract(`ts=1 comm=sshd msg="Failed password for root" dst=10.0.0.1`)
	if f["comm"] != "sshd" {
		t.Errorf("comm=%q", f["comm"])
	}
	if f["dst"] != "10.0.0.1" {
		t.Errorf("dst=%q", f["dst"])
	}
}

var _ = regexp.MustCompile
