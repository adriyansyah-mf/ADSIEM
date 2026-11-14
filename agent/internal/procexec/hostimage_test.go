//go:build linux

package procexec

import (
	"os"
	"testing"
)

// An apache2 worker started before the agent: the eBPF side has no parent
// image for the shell its PHP system() call runs, so /proc fills it in.
func TestWithParentImageFillsUnknownParent(t *testing.T) {
	line := `Image="/bin/sh" CommandLine="sh -c id" PID=20 PPID=10 User=33 Comm="apache2"`
	exe := func(pid uint32) string {
		if pid == 10 {
			return "/usr/sbin/apache2"
		}
		return ""
	}
	want := line + ` ParentImage="/usr/sbin/apache2"`
	if got := withParentImage(line, Exec{PID: 20, PPID: 10, Image: "/bin/sh"}, exe); got != want {
		t.Fatalf("got %s", got)
	}
	known := Exec{PID: 20, PPID: 10, Image: "/bin/sh", ParentImage: "/usr/sbin/nginx"}
	if got := withParentImage(line, known, exe); got != line {
		t.Fatalf("a parent the eBPF side knew stays as sent: %s", got)
	}
	if got := withParentImage(line, Exec{PID: 20, PPID: 11, Image: "/bin/sh"}, exe); got != line {
		t.Fatalf("an exited parent leaves the line alone: %s", got)
	}
}

func TestProcExeReadsOwnProcess(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if got := procExe(uint32(os.Getpid())); got != self {
		t.Fatalf("procExe(self) = %q, want %q", got, self)
	}
}

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
