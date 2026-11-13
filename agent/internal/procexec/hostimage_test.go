//go:build linux

package procexec

import "testing"

func TestWithHostImage(t *testing.T) {
	ex := Exec{PID: 3336932, Image: "/var/tmp/.7625e6d2e"}
	host := func(pid int, p string) string {
		if pid == 3336932 && p == "/var/tmp/.7625e6d2e" {
			return "/var/tmp/systemd-private-x/tmp/.7625e6d2e"
		}
		return ""
	}
	want := `Image="/var/tmp/.7625e6d2e" HostImage="/var/tmp/systemd-private-x/tmp/.7625e6d2e"`
	if got := withHostImage(`Image="/var/tmp/.7625e6d2e"`, ex, host); got != want {
		t.Fatalf("got %s", got)
	}
	if got := withHostImage(`Image="/bin/ls"`, Exec{PID: 1, Image: "/bin/ls"}, host); got != `Image="/bin/ls"` {
		t.Fatalf("same namespace keeps the line: %s", got)
	}
}
