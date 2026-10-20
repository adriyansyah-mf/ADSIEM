//go:build linux

package netwatch

import (
	"reflect"
	"testing"
)

const snap1 = `tcp ESTAB 0 0 10.0.0.5:22 203.0.113.9:51234 users:(("sshd",pid=812,fd=4))
tcp ESTAB 0 0 172.20.0.13:40498 172.20.0.9:8000 users:(("siem-agent",pid=1,fd=9))
tcp TIME-WAIT 0 0 10.0.0.5:443 198.51.100.7:40000
tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=90,fd=5))
tcp ESTAB 0 0 127.0.0.1:5432 127.0.0.1:40100 users:(("postgres",pid=91,fd=6))
tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=70,fd=6))`

func TestOnlyNewConnectionsAreSent(t *testing.T) {
	skip := map[string]bool{"172.20.0.9:8000": true}
	lines, seen := newConnections(snap1, nil, skip)
	want := []string{
		`tcp ESTAB 0 0 10.0.0.5:22 203.0.113.9:51234 users:(("sshd",pid=812,fd=4))`,
		`tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=90,fd=5))`,
		`tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=70,fd=6))`,
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("first snapshot:\n%q\nwant\n%q", lines, want)
	}

	// same sockets again (queue sizes changed, a new fd for the same process) + one new connection
	snap2 := `tcp ESTAB 7 0 10.0.0.5:22 203.0.113.9:51234 users:(("sshd",pid=812,fd=5))
tcp LISTEN 3 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=70,fd=6))
tcp ESTAB 0 0 10.0.0.5:51000 45.9.20.1:4444 users:(("bash",pid=999,fd=3))
tcp ESTAB 0 0 172.20.0.13:40512 172.20.0.9:8000 users:(("siem-agent",pid=1,fd=11))`
	lines, _ = newConnections(snap2, seen, skip)
	want = []string{`tcp ESTAB 0 0 10.0.0.5:51000 45.9.20.1:4444 users:(("bash",pid=999,fd=3))`}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("second snapshot: %q, want %q", lines, want)
	}
}

func TestServerEndpointsAndAddresses(t *testing.T) {
	got := serverEndpoints("https://127.0.0.1")
	if !got["127.0.0.1:443"] {
		t.Fatalf("serverEndpoints: %v", got)
	}
	if !serverEndpoints("http://10.1.2.3:8000/api")["10.1.2.3:8000"] {
		t.Fatal("explicit port")
	}
	for in, want := range map[string][2]string{
		"1.2.3.4:80": {"1.2.3.4", "80"}, "[::1]:443": {"::1", "443"},
		"*:*": {"*", "*"}, "fe80::1%eth0:22": {"fe80::1", "22"},
	} {
		h, p := splitHostPort(in)
		if h != want[0] || p != want[1] {
			t.Errorf("splitHostPort(%q) = %q %q", in, h, p)
		}
	}
}
