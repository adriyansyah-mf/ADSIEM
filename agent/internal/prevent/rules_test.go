package prevent

import (
	"strings"
	"testing"
	"time"
)

var testGuard = &guard{
	paths:  []string{"/usr/bin/bash", "/opt/siem/agent"},
	hashes: map[string]string{strings.Repeat("ab", 32): "/usr/bin/bash"},
}

func TestCompileValidates(t *testing.T) {
	p, errs := compileWith([]Rule{
		{Name: "ok-hash", RuleType: TypeHash, Value: strings.Repeat("CD", 32), Action: ActionBlock},
		{Name: "short-hash", RuleType: TypeHash, Value: "abc", Action: ActionBlock},
		{Name: "rel-path", RuleType: TypePath, Value: "tmp/x", Action: ActionDetect},
		{Name: "no-child", RuleType: TypeParent, Parent: "nginx", Action: ActionBlock},
		{Name: "bad-action", RuleType: TypeDir, Value: "/tmp", Action: "kill"},
		{Name: "bad-type", RuleType: "glob", Value: "/tmp/*", Action: ActionBlock},
		{Name: "dir", RuleType: TypeDir, Value: "/tmp/../tmp/", Action: ActionBlock},
	}, testGuard)
	if len(p.Rules) != 2 || len(errs) != 5 {
		t.Fatalf("rules=%d errs=%v", len(p.Rules), errs)
	}
	if p.Rules[0].Value != strings.Repeat("cd", 32) || p.Rules[1].Value != "/tmp" || p.Rules[1].index != 1 {
		t.Fatalf("normalised wrong: %+v %+v", p.Rules[0].Rule, p.Rules[1].Rule)
	}
}

func TestGuardKeepsProtectedRunning(t *testing.T) {
	p, errs := compileWith([]Rule{
		{Name: "shell", RuleType: TypePath, Value: "/usr/bin/bash", Action: ActionBlock},
		{Name: "usr", RuleType: TypeDir, Value: "/usr", Action: ActionBlock},
		{Name: "root", RuleType: TypeDir, Value: "/", Action: ActionBlock},
		{Name: "agent", RuleType: TypeDir, Value: "/opt/siem", Action: ActionBlock},
		{Name: "bash-hash", RuleType: TypeHash, Value: strings.Repeat("ab", 32), Action: ActionBlock},
		{Name: "tmp", RuleType: TypeDir, Value: "/tmp", Action: ActionBlock},
		{Name: "web-shell", RuleType: TypeParent, Parent: "nginx", Value: "bash", Action: ActionBlock},
	}, testGuard)
	if len(errs) != 5 {
		t.Fatalf("errs = %v", errs)
	}
	for _, c := range p.Rules {
		want := c.Name == "tmp" || c.Name == "web-shell"
		if c.block != want {
			t.Errorf("%s: block=%t, want %t", c.Name, c.block, want)
		}
	}
}

func TestMatch(t *testing.T) {
	p, _ := compileWith([]Rule{
		{Name: "path", RuleType: TypePath, Value: "/opt/tool/x", Action: ActionDetect},
		{Name: "dir", RuleType: TypeDir, Value: "/dev/shm", Action: ActionBlock},
		{Name: "web", RuleType: TypeParent, Parent: "nginx, php-fpm8.2", Value: "sh,dash,bash", Action: ActionBlock},
		{Name: "hash", RuleType: TypeHash, Value: strings.Repeat("ef", 32), Action: ActionBlock},
	}, testGuard)
	hashed := 0
	hash := func(h string) func() (string, bool) {
		return func() (string, bool) { hashed++; return h, true }
	}
	cases := []struct {
		e             Exec
		kernelDecides bool
		want          string
	}{
		{Exec{Path: "/opt/tool/x"}, false, "path"},
		{Exec{Path: "/dev/shm/a/b/payload"}, false, "dir"},
		{Exec{Path: "/dev/shm"}, false, ""},
		{Exec{Path: "/dev/shmx/payload"}, false, ""},
		{Exec{Path: "/usr/bin/dash", Parent: "/usr/sbin/php-fpm8.2"}, false, "web"},
		{Exec{Path: "/usr/bin/dash", Parent: "/usr/bin/sshd"}, false, ""},
		{Exec{Path: "/tmp/z", Hash: hash(strings.Repeat("ef", 32))}, false, "hash"},
		{Exec{Path: "/tmp/z", Hash: hash(strings.Repeat("00", 32))}, false, ""},
		// The LSM engine decides path/dir/parent; fanotify only hashes.
		{Exec{Path: "/dev/shm/payload", Hash: hash(strings.Repeat("00", 32))}, true, ""},
		{Exec{Path: "/dev/shm/payload", Hash: hash(strings.Repeat("ef", 32))}, true, "hash"},
	}
	for i, c := range cases {
		got := ""
		if m := p.Match(c.e, c.kernelDecides); m != nil {
			got = m.Name
		}
		if got != c.want {
			t.Errorf("case %d (%s): got %q, want %q", i, c.e.Path, got, c.want)
		}
	}
	before := hashed
	p.Match(Exec{Path: "/opt/tool/x", Hash: hash("")}, false)
	if hashed != before {
		t.Error("a file matched by path must not be hashed")
	}
}

func TestDecisionLine(t *testing.T) {
	c := &compiled{Rule: Rule{ID: "r1", Name: `web "shell"`, RuleType: TypeParent}, block: true}
	d := Decision{Rule: c, Blocked: true, Engine: "lsm", Path: "/usr/bin/dash", Parent: "php-fpm8.2", Comm: "php-fpm8.2", PID: 9, PPID: 1, UID: 33}
	want := `action=blocked rule="web \"shell\"" rule_id="r1" rule_type=parent engine=lsm Image="/usr/bin/dash" ParentImage="php-fpm8.2" Comm="php-fpm8.2" PID=9 PPID=1 User=33`
	if got := d.line(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestReportDedupes(t *testing.T) {
	var lines []string
	m := &Manager{opts: Options{Push: func(_, l string) { lines = append(lines, l) }}, last: map[string]time.Time{}}
	c := &compiled{Rule: Rule{Name: "r", RuleType: TypeDir}, block: true}
	for i := 0; i < 3; i++ {
		m.report(Decision{Rule: c, Blocked: true, Path: "/tmp/x", Parent: "bash"})
	}
	m.report(Decision{Rule: c, Blocked: true, Path: "/tmp/y", Parent: "bash"})
	if len(lines) != 2 {
		t.Fatalf("a blocked loop must be reported once a minute: %q", lines)
	}
}
