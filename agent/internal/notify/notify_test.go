package notify

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFields(t *testing.T) {
	f := Fields(`event=known_malware action=quarantined label="Agent \"T\"" path="C:\\Users\\a\\x.exe" pid=7 empty=""`)
	if f["action"] != "quarantined" || f["label"] != `Agent "T"` || f["path"] != `C:\Users\a\x.exe` || f["pid"] != "7" ||
		f["empty"] != "" {
		t.Fatalf("%v", f)
	}
}

func TestMessages(t *testing.T) {
	cases := []struct{ logType, line, want string }{
		{"known_malware", `event=known_malware action=quarantined trigger=file label="AgentTesla" path="C:\\x.exe"`,
			"found and locked so it cannot run:\nC:\\x.exe (AgentTesla)"},
		{"known_malware", `event=known_malware action=terminated trigger=exec label="unknown" path="C:\\y.exe"`,
			"program was stopped:\nC:\\y.exe"},
		{"known_malware", `event=known_malware action=detected trigger=file label="Emotet" path="/tmp/z"`,
			"Your security team has been alerted"},
		{"yara_match", `event=yara_match rule="mimikatz" severity=critical file="C:\\m.exe"`, "(rule mimikatz)"},
		{"yara_match", `event=yara_match rule="eicar" severity=low file="C:\\e.txt"`, ""},
		{"windows_exec_prevention", `action=terminated rule="no tools" Image="C:\\nc.exe"`, "security policy:\nC:\\nc.exe"},
		{"windows_exec_prevention", `action=detected rule="watch" Image="C:\\nc.exe"`, ""},
		{"ransomware_activity", `detection=canary confirmed=true response=kill Image="C:\\r.exe" Killed=1`,
			"detected and the program was stopped:\nC:\\r.exe"},
		{"ransomware_activity", `detection=canary confirmed=false response=none`, ""},
		{"windows_etw_image", `EventID=7 Image="C:\\x.exe"`, ""},
		{"known_malware", `event=known_malware action=detected trigger=file label="Lumma" path="C:\\v.exe" match=tlsh distance=12`, ""},
		{"ml_detection", `event=ml_detection action=quarantined level=malicious kind=pe path="C:\\d.exe"`,
			"looks malicious was found and locked so it cannot run:\nC:\\d.exe"},
		{"ml_detection", `event=ml_detection action=detected level=malicious kind=elf path="/tmp/m"`,
			"security team has been alerted"},
		{"ml_detection", `event=ml_detection action=detected level=suspicious kind=pe path="C:\\s.exe"`, ""},
	}
	for _, c := range cases {
		got := Message(c.logType, c.line)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s %s:\n got %q\nwant ...%q...", c.logType, c.line, got, c.want)
		}
	}
	long := strings.Repeat("a", 300)
	if got := Message("known_malware", `action=detected path="`+long+`"`); strings.Contains(got, long) || !strings.Contains(got, "...") {
		t.Fatal("long paths are shortened")
	}
}

func TestDedupeAndRateLimit(t *testing.T) {
	var mu sync.Mutex
	var shown []string
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	n := &Notifier{recent: map[string]time.Time{}, now: func() time.Time { return now },
		show: func(_, m string) error { mu.Lock(); shown = append(shown, m); mu.Unlock(); return nil }}
	line := func(p string) string { return `action=quarantined label="X" path="` + p + `"` }
	n.Observe("known_malware", line("a"))
	n.Observe("known_malware", line("a")) // same message: once per 5 minutes
	for _, p := range []string{"b", "c", "d", "e", "f", "g"} {
		n.Observe("known_malware", line(p))
	}
	now = now.Add(6 * time.Minute)
	n.Observe("known_malware", line("a")) // again after 5 minutes
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		count := len(shown)
		mu.Unlock()
		if count >= 6 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(shown) != 6 { // a, b, c, d, e (5 a minute), then a again
		t.Fatalf("shown %d: %q", len(shown), shown)
	}
	var nilNotifier *Notifier
	nilNotifier.Observe("known_malware", line("z")) // no platform: nothing, no panic
}
