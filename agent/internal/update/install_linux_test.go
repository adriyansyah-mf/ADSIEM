//go:build linux

package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInstallArgv(t *testing.T) {
	deb, _ := installArgv("deb", "/var/lib/siem-agent/update/pkg/a.deb")
	if !reflect.DeepEqual(deb, []string{"dpkg", "--force-confold", "--force-confdef", "-i", "/var/lib/siem-agent/update/pkg/a.deb"}) {
		t.Fatalf("deb %v", deb)
	}
	rpm, _ := installArgv("rpm", "/p/a.rpm")
	if !reflect.DeepEqual(rpm, []string{"rpm", "-U", "--oldpackage", "--replacepkgs", "/p/a.rpm"}) {
		t.Fatalf("rpm %v", rpm)
	}
	if _, err := installArgv("msi", "x"); err == nil {
		t.Fatal("msi accepted on linux")
	}
	full := systemdRunArgv(deb, "/l/install.log", "/l/install.result", time.Unix(1700000000, 0))
	want := []string{"systemd-run", "--unit=siem-agent-update-1700000000", "--collect", "--quiet",
		"--setenv=DEBIAN_FRONTEND=noninteractive", "/bin/sh", "-c", installScript, "sh", "/l/install.log", "/l/install.result"}
	if !reflect.DeepEqual(full[:len(want)], want) || !reflect.DeepEqual(full[len(want):], deb) {
		t.Fatalf("systemd-run %v", full)
	}
}

// The wrapper the transient unit runs: output to the log, status to the
// result file, and the service started again after a failure.
func TestInstallScript(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// a fake systemctl records what the script asks of it
	calls := filepath.Join(dir, "systemctl.calls")
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\necho \"$@\" >>"+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(argv ...string) (string, string) {
		log, res := filepath.Join(dir, "install.log"), filepath.Join(dir, "install.result")
		cmd := exec.Command("/bin/sh", append([]string{"-c", installScript, "sh", log, res}, argv...)...)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		_ = cmd.Run()
		l, _ := os.ReadFile(log)
		r, _ := os.ReadFile(res)
		return string(l), strings.TrimSpace(string(r))
	}
	if log, rc := run("sh", "-c", "echo unpacking; exit 0"); rc != "0" || !strings.Contains(log, "unpacking") {
		t.Fatalf("success: rc %q log %q", rc, log)
	}
	if _, err := os.Stat(calls); err == nil {
		t.Fatal("service started after a successful install")
	}
	if log, rc := run("sh", "-c", "echo broken >&2; exit 2"); rc != "2" || !strings.Contains(log, "broken") {
		t.Fatalf("failure: rc %q log %q", rc, log)
	}
	if got, _ := os.ReadFile(calls); strings.TrimSpace(string(got)) != "start siem-agent.service" {
		t.Fatalf("after a failure systemctl got %q", got)
	}
}
