package linsensor

import (
	"strings"
	"testing"
	"time"
)

func accessProc() fakeProc {
	return fakeProc{exe: map[uint32]string{
		10:  "/tmp/.x/mimipenguin",
		700: "/usr/sbin/sshd",
		20:  "/usr/bin/gdb",
	}}
}

func TestProcessMemoryAccessLines(t *testing.T) {
	p, s, _, now := newTestProcessor(accessProc())
	ev := rawEvent{kind: kindVMAccess, pid: 10, tgid: 10, ppid: 1, uid: 0, comm: "mimipenguin", arg0: 700, arg1: 0}
	p.handle(ev)
	p.handle(ev) // same reader, target, action: once per 10 minutes
	want := `linux_process_access action=vm_read TargetPID=700 TargetImage="/usr/sbin/sshd" Image="/tmp/.x/mimipenguin" ` +
		`Comm="mimipenguin" PID=10 PPID=1 User=0 EUID=0`
	if len(s.lines) != 1 || s.lines[0] != want {
		t.Fatalf("lines %q\nwant %q", s.lines, want)
	}
	ev.arg1 = 1
	p.handle(ev)
	if len(s.lines) != 2 || !strings.Contains(s.lines[1], "action=vm_write") {
		t.Fatalf("write: %q", s.lines)
	}
	*now = now.Add(11 * time.Minute)
	ev.arg1 = 0
	p.handle(ev)
	if len(s.lines) != 3 {
		t.Fatal("reported again after the window")
	}
	p.handle(rawEvent{kind: kindVMAccess, tgid: 10, arg0: 10}) // its own memory
	if len(s.lines) != 3 {
		t.Fatal("own memory is not reported")
	}
}

func TestProcMemAndShadowOpens(t *testing.T) {
	p, s, files, _ := newTestProcessor(accessProc())
	// read-only open of /proc/700/mem (the kernel passes it on)
	p.handle(rawEvent{kind: kindOpen, pid: 10, tgid: 10, comm: "mimipenguin", path: "/proc/700/mem", arg0: 0})
	// write open of another's memory: injection; it used to be dropped as /proc
	p.handle(rawEvent{kind: kindOpen, pid: 10, tgid: 10, comm: "mimipenguin", path: "/proc/700/mem", arg0: oRdwr})
	// /etc/shadow read
	p.handle(rawEvent{kind: kindOpen, pid: 10, tgid: 10, comm: "mimipenguin", path: "/etc/shadow", arg0: 0})
	p.handle(rawEvent{kind: kindOpen, pid: 10, tgid: 10, comm: "mimipenguin", path: "/etc/shadow", arg0: 0})
	got := strings.Join(s.lines, "\n")
	for _, w := range []string{
		`linux_process_access action=mem_read TargetPID=700 TargetImage="/usr/sbin/sshd"`,
		`linux_process_access action=mem_write TargetPID=700`,
		`linux_file_event action=read TargetFilename="/etc/shadow" Image="/tmp/.x/mimipenguin"`,
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
	if strings.Count(got, "action=read") != 1 {
		t.Fatalf("a repeated read is reported once:\n%s", got)
	}
	if len(*files) != 0 {
		t.Fatalf("reads are not file activity for the anti-ransomware hook: %v", *files)
	}
	for _, path := range []string{"/proc/self/mem", "/proc/700/maps", "/proc/x/mem"} {
		if _, ok := procMem(path); ok {
			t.Errorf("%s is not /proc/<pid>/mem", path)
		}
	}
}

func TestAccessGroupOff(t *testing.T) {
	p, s, _, _ := newTestProcessor(accessProc(), GroupAccess)
	p.handle(rawEvent{kind: kindVMAccess, tgid: 10, arg0: 700})
	p.handle(rawEvent{kind: kindOpen, tgid: 10, path: "/etc/shadow"})
	p.handle(rawEvent{kind: kindOpen, tgid: 10, path: "/proc/700/mem", arg0: oRdwr})
	if len(s.lines) != 0 {
		t.Fatalf("access off: %q", s.lines)
	}
}
