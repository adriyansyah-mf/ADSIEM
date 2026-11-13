package linsensor

import (
	"strings"
	"testing"
)

// A process in another mount namespace (apache with PrivateTmp) writes
// /var/tmp/x, which the host has elsewhere: the line carries both.
func TestFileEventCarriesHostPath(t *testing.T) {
	p, s, files, _ := newTestProcessor(fakeProc{exe: map[uint32]string{33: "/usr/bin/curl"}})
	priv := "/var/tmp/systemd-private-abc-apache2.service-KsXgSN/tmp/.7625e6d2e"
	p.hostPath = func(tgid uint32, path string) string {
		if tgid == 33 && path == "/var/tmp/.7625e6d2e" {
			return priv
		}
		return ""
	}
	p.handle(rawEvent{kind: kindOpen, tgid: 33, pid: 33, path: "/var/tmp/.7625e6d2e", arg0: oCreat | oWronly, comm: "curl"})
	p.handle(rawEvent{kind: kindOpen, tgid: 44, pid: 44, path: "/home/u/a", arg0: oCreat | oWronly, comm: "vim"})
	if len(s.lines) != 2 || !strings.Contains(s.lines[0], `TargetFilename="/var/tmp/.7625e6d2e" HostTargetFilename="`+priv+`"`) {
		t.Fatalf("lines %q", s.lines)
	}
	if strings.Contains(s.lines[1], "HostTargetFilename") {
		t.Fatalf("same namespace: no host path, got %q", s.lines[1])
	}
	if (*files)[0].HostPath != priv {
		t.Fatalf("guards get the host path: %+v", (*files)[0])
	}
}
