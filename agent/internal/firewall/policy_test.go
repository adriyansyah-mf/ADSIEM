package firewall

import (
	"testing"
	"time"
)

func TestRuleValidate(t *testing.T) {
	ok := []Rule{
		{Action: ActionBlock, CIDR: "203.0.113.5"},
		{Action: ActionBlock, CIDR: "203.0.113.0/24"},
		{Action: ActionBlock, CIDR: "203.0.113.5", Proto: "tcp", Port: 22},
		{Action: ActionAllow, CIDR: "10.0.0.0/8", Direction: DirInbound},
		{Action: ActionBlock, CIDR: "203.0.113.5", TTL: 30 * time.Second},
		{Action: ActionBlock, CIDR: "203.0.113.5", Proto: "icmp"},
	}
	for _, r := range ok {
		if err := r.normalize().Validate(); err != nil {
			t.Errorf("expected valid, got %v for %+v", err, r)
		}
	}

	bad := []Rule{
		{Action: "deny", CIDR: "203.0.113.5"},
		{CIDR: "not-an-ip"},
		{CIDR: "2001:db8::1"},
		{CIDR: "203.0.113.5", Proto: "sctp"},
		{CIDR: "203.0.113.5", Port: 70000},
		{CIDR: "203.0.113.5", Port: 22},
		{CIDR: "203.0.113.5", Proto: "icmp", Port: 22},
		{CIDR: "203.0.113.5", Direction: "sideways"},
		{CIDR: "203.0.113.5", TTL: -time.Second},
	}
	for _, r := range bad {
		if err := r.normalize().Validate(); err == nil {
			t.Errorf("expected error, got nil for %+v", r)
		}
	}
}

func TestRuleKeyIsStableAndDistinct(t *testing.T) {
	a := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirInbound}.normalize()
	b := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirInbound}.normalize()
	if a.Key() != b.Key() {
		t.Fatalf("same rule produced different keys: %q vs %q", a.Key(), b.Key())
	}

	c := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirOutbound}.normalize()
	d := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Proto: "tcp", Port: 22, Direction: DirInbound}.normalize()
	if a.Key() == c.Key() || a.Key() == d.Key() || c.Key() == d.Key() {
		t.Fatalf("distinct rules collided: %q %q %q", a.Key(), c.Key(), d.Key())
	}
}

func TestParseRule(t *testing.T) {
	r, err := ParseRule(map[string]any{
		"ip":               "203.0.113.9",
		"duration_seconds": float64(120),
		"reason":           "manual",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.CIDR != "203.0.113.9" || r.Action != ActionBlock || r.TTL != 120*time.Second {
		t.Fatalf("unexpected rule: %+v", r)
	}

	if _, err := ParseRule(map[string]any{"ip": "999.1.1.1"}); err == nil {
		t.Fatal("expected invalid ip error")
	}
	if _, err := ParseRule(map[string]any{}); err == nil {
		t.Fatal("expected missing cidr error")
	}
}

func TestSetElement(t *testing.T) {
	cases := []struct {
		name  string
		rule  Rule
		set   string
		key   string
	}{
		{"ip inbound", Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirInbound}.normalize(), setIPIn, "203.0.113.5"},
		{"ip outbound", Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirOutbound}.normalize(), setIPOut, "203.0.113.5"},
		{"ip both prefers input set", Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirBoth}.normalize(), setIPIn, "203.0.113.5"},
		{"svc inbound", Rule{Action: ActionBlock, CIDR: "203.0.113.5", Proto: "tcp", Port: 22, Direction: DirInbound}.normalize(), setSvcIn, "203.0.113.5 . tcp . 22"},
		{"svc outbound", Rule{Action: ActionBlock, CIDR: "203.0.113.5", Proto: "udp", Port: 53, Direction: DirOutbound}.normalize(), setSvcOut, "203.0.113.5 . udp . 53"},
	}
	for _, c := range cases {
		key, set := setElement(c.rule)
		if set != c.set || key != c.key {
			t.Errorf("%s: got (%q,%q) want (%q,%q)", c.name, set, key, c.set, c.key)
		}
	}
}

func TestTimeoutSuffix(t *testing.T) {
	if got := nftTimeoutSuffix(Rule{TTL: 0}); got != "" {
		t.Errorf("expected empty suffix, got %q", got)
	}
	if got := nftTimeoutSuffix(Rule{TTL: 90 * time.Second}); got != " timeout 90s" {
		t.Errorf("expected ' timeout 90s', got %q", got)
	}
}

func TestApplyArgvIncludesTimeout(t *testing.T) {
	r := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirInbound, TTL: 60 * time.Second}.normalize()
	argv := nftApplyArgv(r)
	want := []string{"add", "element", "inet", tableName, setIPIn, "{ 203.0.113.5 timeout 60s }"}
	if len(argv) != len(want) {
		t.Fatalf("argv length %d want %d: %v", len(argv), len(want), argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d]=%q want %q (full: %v)", i, argv[i], want[i], argv)
		}
	}
}

func TestApplyArgvWrapsElementInBraces(t *testing.T) {
	r := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirInbound, TTL: 60 * time.Second}.normalize()
	argv := nftApplyArgv(r)
	last := argv[len(argv)-1]
	if last != "{ 203.0.113.5 timeout 60s }" {
		t.Fatalf("nft requires the element in braces, got %q", last)
	}
}

func TestRemoveArgvHasNoTimeout(t *testing.T) {
	r := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirInbound, TTL: 60 * time.Second}.normalize()
	argv := nftRemoveArgv(r)
	last := argv[len(argv)-1]
	if last != "{ 203.0.113.5 }" {
		t.Fatalf("delete element must use the bare key in braces, got %q", last)
	}
}

func TestApplyArgvSvcKey(t *testing.T) {
	r := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Proto: "tcp", Port: 22, Direction: DirInbound}.normalize()
	argv := nftApplyArgv(r)
	last := argv[len(argv)-1]
	if last != "{ 203.0.113.5 . tcp . 22 }" {
		t.Fatalf("unexpected svc element %q", last)
	}
	if argv[4] != setSvcIn {
		t.Fatalf("unexpected set %q", argv[4])
	}
}

func TestParseNftList(t *testing.T) {
	raw := `table inet siem_fw {
	set blocked_v4_in {
		type ipv4_addr
		flags timeout
		elements = { 203.0.113.5 timeout 1m expires 59s996ms,
			     203.0.113.6 }
	}

	set blocked_svc_in {
		type ipv4_addr . inet_proto . inet_service
		flags timeout
		elements = { 198.51.100.7 . tcp . 22 timeout 10m expires 9m59s }
	}
}`
	rules := parseNftList(raw)
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d: %+v", len(rules), rules)
	}

	byCIDR := map[string]Rule{}
	for _, r := range rules {
		byCIDR[r.CIDR] = r
	}

	if r, ok := byCIDR["203.0.113.5"]; !ok {
		t.Fatal("missing 203.0.113.5")
	} else if r.TTL != time.Minute {
		t.Errorf("expected 1m ttl, got %s", r.TTL)
	}

	if r, ok := byCIDR["203.0.113.6"]; !ok {
		t.Fatal("missing 203.0.113.6")
	} else if r.TTL != 0 {
		t.Errorf("expected no ttl, got %s", r.TTL)
	}

	if r, ok := byCIDR["198.51.100.7"]; !ok {
		t.Fatal("missing service rule")
	} else if r.Port != 22 || r.Proto != "tcp" || r.Direction != DirInbound {
		t.Errorf("bad service rule: %+v", r)
	}
}

func TestNoopBackendRecordsCommands(t *testing.T) {
	n := NewNoop(true)
	if n.Available() {
		t.Fatal("noop must report unavailable")
	}
	r := Rule{Action: ActionBlock, CIDR: "203.0.113.5", Direction: DirInbound, TTL: 45 * time.Second}.normalize()
	if err := n.Apply(r); err != nil {
		t.Fatal(err)
	}
	cmds := n.PlannedCommands()
	if len(cmds) != 1 {
		t.Fatalf("expected 1 planned command, got %d", len(cmds))
	}
	if want := "nft [add element inet siem_fw blocked_v4_in { 203.0.113.5 timeout 45s }]"; cmds[0] != want {
		t.Fatalf("got %q want %q", cmds[0], want)
	}
	listed, _ := n.List()
	if len(listed) != 1 || listed[0].CIDR != "203.0.113.5" {
		t.Fatalf("list mismatch: %+v", listed)
	}
}
