package detect

import (
	"errors"
	"regexp"
	"testing"
	"time"
)

var errTest = errors.New("simulated blocker failure")

type fakeBlocker struct {
	blocked map[string]time.Duration
	err     error
	calls   int
}

func newFakeBlocker() *fakeBlocker {
	return &fakeBlocker{blocked: map[string]time.Duration{}}
}

func (f *fakeBlocker) Add(ruleKey, ip string, ttl time.Duration) error {
	if f.err != nil {
		return f.err
	}
	f.calls++
	f.blocked[ip] = ttl
	return nil
}

func (f *fakeBlocker) BlockedCount() int { return len(f.blocked) }

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func sshRule() Rule {
	return Rule{
		Key:       "ssh_bruteforce",
		LogType:   "linux_auth",
		Match:     regexp.MustCompile(`Failed password`),
		GroupExpr: regexp.MustCompile(`ip=(\d{1,3}(?:\.\d{1,3}){3})`),
		Threshold: 3,
		Window:    60 * time.Second,
		Cooldown:  time.Minute,
		Action:    actionBlock,
		BlockFor:  10 * time.Minute,
		Title:     "Local: SSH brute force",
		Severity:  SeverityHigh,
		enabled:   true,
	}
}

func newEngineWith(rules []Rule, blk Blocker, c *clock) *Engine {
	return New(Options{Rules: rules, Blocker: blk, Now: c.now})
}

const failedLine = `ts=2026-01-01 pid=1 comm=sshd ip=203.0.113.9 msg="Failed password for root"`

func TestThresholdFiresExactlyAtCount(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	blk := newFakeBlocker()
	e := newEngineWith([]Rule{sshRule()}, blk, c)

	if dets := e.Observe("linux_auth", failedLine); len(dets) != 0 {
		t.Fatalf("first hit must not fire: %+v", dets)
	}
	c.advance(time.Second)
	e.Observe("linux_auth", failedLine)
	if dets := e.Observe("linux_auth", failedLine); len(dets) != 1 {
		t.Fatalf("third hit must fire once, got %d", len(dets))
	}
	if blk.blocked["203.0.113.9"] != 10*time.Minute {
		t.Fatalf("expected a 10m block, got %v", blk.blocked)
	}
}

func TestWindowExpiryPreventsFiring(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	e := newEngineWith([]Rule{sshRule()}, newFakeBlocker(), c)

	e.Observe("linux_auth", failedLine)
	c.advance(90 * time.Second)
	e.Observe("linux_auth", failedLine)
	c.advance(90 * time.Second)
	dets := e.Observe("linux_auth", failedLine)
	if len(dets) != 0 {
		t.Fatal("hits outside the window must not accumulate")
	}
}

func TestCooldownSuppressesRepeat(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	e := newEngineWith([]Rule{sshRule()}, newFakeBlocker(), c)

	for i := 0; i < 3; i++ {
		e.Observe("linux_auth", failedLine)
	}
	c.advance(10 * time.Second)
	for i := 0; i < 3; i++ {
		if dets := e.Observe("linux_auth", failedLine); len(dets) != 0 {
			t.Fatal("cooldown must suppress repeated firing")
		}
	}
	c.advance(2 * time.Minute)
	fired := false
	for i := 0; i < 3; i++ {
		if dets := e.Observe("linux_auth", failedLine); len(dets) > 0 {
			fired = true
		}
	}
	if !fired {
		t.Fatal("rule must fire again after the cooldown elapses")
	}
}

func TestGroupsAreIndependent(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	e := newEngineWith([]Rule{sshRule()}, newFakeBlocker(), c)

	lineA := `ip=203.0.113.1 msg="Failed password"`
	lineB := `ip=203.0.113.2 msg="Failed password"`

	e.Observe("linux_auth", lineA)
	e.Observe("linux_auth", lineB)
	e.Observe("linux_auth", lineA)
	if dets := e.Observe("linux_auth", lineA); len(dets) != 1 {
		t.Fatalf("group A must fire, got %d", len(dets))
	}
}

func TestMissingGroupIsSkipped(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	e := newEngineWith([]Rule{sshRule()}, newFakeBlocker(), c)

	for i := 0; i < 5; i++ {
		if dets := e.Observe("linux_auth", `msg="Failed password"`); len(dets) != 0 {
			t.Fatal("events without a group value must not be pooled")
		}
	}
}

func TestWrongLogTypeIsIgnored(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	e := newEngineWith([]Rule{sshRule()}, newFakeBlocker(), c)

	for i := 0; i < 5; i++ {
		if dets := e.Observe("apache_access", failedLine); len(dets) != 0 {
			t.Fatal("log type must gate the rule")
		}
	}
}

func TestBlocksPerMinuteCap(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	blk := newFakeBlocker()
	rule := sshRule()
	rule.Cooldown = time.Second
	e := New(Options{Rules: []Rule{rule}, Blocker: blk, Now: c.now, MaxBlocksPerMin: 2})

	suppressed := 0
	for i := 0; i < 6; i++ {
		line := `ip=203.0.113.` + string(rune('1'+i)) + ` msg="Failed password"`
		for j := 0; j < 3; j++ {
			for _, d := range e.Observe("linux_auth", line) {
				if d.BlockedErr != "" {
					suppressed++
				}
			}
		}
		c.advance(2 * time.Second)
	}

	if blk.calls != 2 {
		t.Fatalf("expected exactly 2 blocks under the cap, got %d", blk.calls)
	}
	if suppressed == 0 {
		t.Fatal("suppressed blocks must report an error on the detection")
	}
}

func TestBlockedEntryCap(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	blk := newFakeBlocker()
	for i := 0; i < 5; i++ {
		blk.blocked["10.0.0."+string(rune('1'+i))] = time.Minute
	}
	rule := sshRule()
	rule.Cooldown = time.Second
	e := New(Options{Rules: []Rule{rule}, Blocker: blk, Now: c.now, MaxBlocked: 5})

	line := `ip=203.0.113.44 msg="Failed password"`
	var dets []Detection
	for j := 0; j < 3; j++ {
		dets = e.Observe("linux_auth", line)
	}
	if len(dets) != 1 || dets[0].BlockedErr == "" {
		t.Fatalf("entry cap must suppress the block: %+v", dets)
	}
	if dets[0].Blocked {
		t.Fatal("a capped block must not be reported as applied")
	}
}

func TestBlockerErrorIsReported(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	blk := newFakeBlocker()
	blk.err = errTest
	e := newEngineWith([]Rule{sshRule()}, blk, c)

	var last []Detection
	for i := 0; i < 3; i++ {
		last = e.Observe("linux_auth", failedLine)
	}
	if len(last) != 1 || last[0].BlockedErr == "" {
		t.Fatalf("blocker failure must surface in the detection: %+v", last)
	}
	if last[0].Blocked {
		t.Fatal("failed block must not be reported as blocked")
	}
}

func TestDisabledRulesNeverRun(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	rule := sshRule()
	rule.enabled = false
	e := newEngineWith([]Rule{rule}, newFakeBlocker(), c)

	for i := 0; i < 10; i++ {
		if dets := e.Observe("linux_auth", failedLine); len(dets) != 0 {
			t.Fatal("disabled rule must not fire")
		}
	}
	if got := len(e.EnabledRules()); got != 0 {
		t.Fatalf("expected no enabled rules, got %d", got)
	}
}

func TestApplyEnabledRejectsUnknownKey(t *testing.T) {
	if _, err := ApplyEnabled(DefaultRules(), []string{"nope"}); err == nil {
		t.Fatal("unknown rule key must be rejected")
	}
	rules, err := ApplyEnabled(DefaultRules(), []string{"ssh_bruteforce"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	enabled := 0
	for _, r := range rules {
		if r.enabled {
			enabled++
		}
	}
	if enabled != 1 {
		t.Fatalf("expected exactly one enabled rule, got %d", enabled)
	}
}

func TestDefaultRulesAreValidWhenEnabled(t *testing.T) {
	for _, r := range DefaultRules() {
		r.enabled = true
		if err := r.Validate(); err != nil {
			t.Errorf("default rule %s invalid: %v", r.Key, err)
		}
	}
}

func TestGroupExprExtractsFromSyslogLine(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	blk := newFakeBlocker()
	rule := sshRule()
	rule.Match = regexp.MustCompile(`Failed password`)
	rule.GroupExpr = regexp.MustCompile(`from (\d{1,3}(?:\.\d{1,3}){3})`)
	e := newEngineWith([]Rule{rule}, blk, c)

	line := `2026-10-18T13:40:51+00:00 host sshd-session[333]: Failed password for root from 172.20.0.13 port 36642 ssh2`
	var dets []Detection
	for i := 0; i < 3; i++ {
		dets = e.Observe("linux_auth", line)
	}
	if len(dets) != 1 {
		t.Fatalf("syslog line must be grouped and detected, got %d", len(dets))
	}
	if dets[0].Group != "172.20.0.13" {
		t.Fatalf("group=%q want the attacker IP", dets[0].Group)
	}
	if blk.blocked["172.20.0.13"] == 0 {
		t.Fatal("the extracted IP must be the one blocked")
	}
}

func TestGroupExprMissingValueSkips(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	rule := sshRule()
	rule.Match = regexp.MustCompile(`Failed password`)
	rule.GroupExpr = regexp.MustCompile(`from (\d{1,3}(?:\.\d{1,3}){3})`)
	e := newEngineWith([]Rule{rule}, newFakeBlocker(), c)

	for i := 0; i < 5; i++ {
		if dets := e.Observe("linux_auth", "sshd: Failed password for root"); len(dets) != 0 {
			t.Fatal("line without an address must not fire")
		}
	}
}
