//go:build linux

package webblock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallRemoveTrustWithFakeTool(t *testing.T) {
	d := t.TempDir()
	oldL, oldR, oldD, oldH := lookPath, runTool, debianAnchor, rhelAnchor
	defer func() { lookPath, runTool, debianAnchor, rhelAnchor = oldL, oldR, oldD, oldH }()
	debianAnchor = filepath.Join(d, "deb", "adsiem-webblock.crt")
	rhelAnchor = filepath.Join(d, "rhel", "adsiem-webblock.crt")
	var ran []string
	runTool = func(name string, args ...string) error { ran = append(ran, name); return nil }

	lookPath = func(string) (string, error) { return "", errors.New("none") }
	if err := installTrust([]byte{1}, "x"); err == nil || err.Error() != "no supported trust store tool" {
		t.Fatalf("got %v", err)
	}

	lookPath = func(n string) (string, error) {
		if n == "update-ca-trust" {
			return "/x", nil
		}
		return "", errors.New("none")
	}
	ca, _ := newTestCA(t)
	if err := installTrust(ca.DER, ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if !trustInstalled(ca.Fingerprint()) || len(ran) != 1 || ran[0] != "update-ca-trust" {
		t.Fatalf("ran=%v", ran)
	}
	if err := removeTrust(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rhelAnchor); err == nil || trustInstalled(ca.Fingerprint()) || len(ran) != 2 {
		t.Fatalf("anchor not removed, ran=%v", ran)
	}
}
