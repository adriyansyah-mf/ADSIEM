//go:build linux

package update

import (
	"reflect"
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
	full := systemdRunArgv(deb, "/l/install.log", time.Unix(1700000000, 0))
	want := []string{"systemd-run", "--unit=siem-agent-update-1700000000", "--collect", "--wait", "--quiet",
		"--setenv=DEBIAN_FRONTEND=noninteractive", "/bin/sh", "-c", `log=$1; shift; exec "$@" >"$log" 2>&1`, "sh", "/l/install.log"}
	if !reflect.DeepEqual(full[:len(want)], want) || !reflect.DeepEqual(full[len(want):], deb) {
		t.Fatalf("systemd-run %v", full)
	}
}
