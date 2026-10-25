package detect

import (
	"strings"
	"testing"
	"time"
)

// Exact output of winevent.FormatXML for a 4625 (tests/agent/winevent_format_test.go).
func logonFailed(ip, logonType string) string {
	return `EventID=4625 Channel="Security" Provider="Microsoft-Windows-Security-Auditing" Computer="WIN01.corp.local" ` +
		`RecordID="98765" Level="0" Task="12544" Opcode="0" Keywords="0x8010000000000000" ` +
		`TimeCreated="2026-10-18T03:00:00.1234567Z" ProcessID="672" IpAddress="` + ip + `" IpPort="51234" ` +
		`LogonType="` + logonType + `" SubjectUserSid="S-1-0-0" TargetDomainName="CORP" TargetUserName="administrator" WorkstationName="KALI"`
}

// windowsRule enables only windows_logon_bruteforce; ApplyEnabled returns
// every rule with its enabled flag, the enabled one last checked here.
func windowsRule(t *testing.T) []Rule {
	t.Helper()
	rules, err := ApplyEnabled(DefaultRules(), []string{"windows_logon_bruteforce"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Key == "windows_logon_bruteforce" && r.Enabled() {
			return rules
		}
	}
	t.Fatal("windows_logon_bruteforce not enabled")
	return nil
}

func ruleByKey(rules []Rule, key string) Rule {
	for _, r := range rules {
		if r.Key == key {
			return r
		}
	}
	return Rule{}
}

func TestWindowsLogonBruteForceBlocksTheSource(t *testing.T) {
	rules := windowsRule(t)
	blk := newFakeBlocker()
	e := newEngineWith(rules, blk, &clock{t: time.Unix(1000, 0)})
	var dets []Detection
	for i := 0; i < 10; i++ {
		dets = append(dets, e.Observe("windows_security", logonFailed("203.0.113.7", "10"))...)
	}
	if len(dets) != 1 || !dets[0].Blocked {
		t.Fatalf("detections %+v", dets)
	}
	if ttl, ok := blk.blocked["203.0.113.7"]; !ok || ttl != 10*time.Minute {
		t.Fatalf("blocked %v", blk.blocked)
	}
}

func TestWindowsLogonBruteForceMatchesOnlyNetworkAndRDP(t *testing.T) {
	r := ruleByKey(windowsRule(t), "windows_logon_bruteforce")
	for _, c := range []struct {
		line, group string
		ok          bool
	}{
		{logonFailed("203.0.113.7", "3"), "203.0.113.7", true},
		{logonFailed("::ffff:198.51.100.4", "10"), "198.51.100.4", true},
		{logonFailed("203.0.113.7", "2"), "", false}, // interactive at the console
		{logonFailed("-", "3"), "", false},           // no source address to block
		{strings.Replace(logonFailed("203.0.113.7", "3"), "EventID=4625", "EventID=4624", 1), "", false},
	} {
		group, ok := r.matches("windows_security", c.line)
		if ok != c.ok || group != c.group {
			t.Errorf("%s: got %q %v, want %q %v", c.line[:60], group, ok, c.group, c.ok)
		}
	}
	if _, ok := r.matches("linux_auth", logonFailed("203.0.113.7", "3")); ok {
		t.Error("matched another log type")
	}
}
