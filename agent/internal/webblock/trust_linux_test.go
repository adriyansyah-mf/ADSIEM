//go:build linux

package webblock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fakeTrust(t *testing.T) *[]string {
	t.Helper()
	d := t.TempDir()
	oldL, oldR, oldD, oldH := lookPath, runTool, debianAnchor, rhelAnchor
	t.Cleanup(func() { lookPath, runTool, debianAnchor, rhelAnchor = oldL, oldR, oldD, oldH })
	debianAnchor = filepath.Join(d, "deb", "adsiem-webblock.crt")
	rhelAnchor = filepath.Join(d, "rhel", "adsiem-webblock.crt")
	ran := &[]string{}
	runTool = func(path string, args ...string) error { *ran = append(*ran, path); return nil }
	return ran
}

func TestInstallRemoveTrustWithFakeTool(t *testing.T) {
	ran := fakeTrust(t)
	lookPath = func(string) (string, error) { return "", errors.New("none") }
	if err := installTrust([]byte{1}, "x"); err == nil || err.Error() != "no supported trust store tool" {
		t.Fatalf("got %v", err)
	}

	lookPath = func(n string) (string, error) {
		if n == "update-ca-trust" {
			return "/abs/update-ca-trust", nil
		}
		return "", errors.New("none")
	}
	ca, _ := newTestCA(t)
	if err := installTrust(ca.DER, ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if !trustInstalled(ca.Fingerprint()) || len(*ran) != 1 || (*ran)[0] != "/abs/update-ca-trust" {
		t.Fatalf("ran=%v", *ran)
	}
	if err := removeTrust(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rhelAnchor); err == nil || trustInstalled(ca.Fingerprint()) || len(*ran) != 2 {
		t.Fatalf("anchor not removed, ran=%v", *ran)
	}
}

func TestFailedToolRemovesAnchor(t *testing.T) {
	fakeTrust(t)
	lookPath = func(n string) (string, error) { return "/abs/" + n, nil }
	runTool = func(string, ...string) error { return errors.New("boom") }
	ca, _ := newTestCA(t)
	if err := installTrust(ca.DER, ca.Fingerprint()); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(debianAnchor); err == nil {
		t.Fatal("anchor left behind")
	}
	if trustInstalled(ca.Fingerprint()) {
		t.Fatal("reported installed after failure")
	}
}
