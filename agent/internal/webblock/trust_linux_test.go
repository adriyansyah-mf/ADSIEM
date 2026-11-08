//go:build linux

package webblock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fakeTrust(t *testing.T) *[]string {
	t.Helper()
	d := t.TempDir()
	oldL, oldR, oldD, oldH, oldS := lookPath, runTool, debianAnchor, rhelAnchor, suseAnchor
	t.Cleanup(func() { lookPath, runTool, debianAnchor, rhelAnchor, suseAnchor = oldL, oldR, oldD, oldH, oldS })
	debianAnchor = filepath.Join(d, "deb", "adsiem-webblock.crt")
	rhelAnchor = filepath.Join(d, "rhel", "adsiem-webblock.crt")
	suseAnchor = filepath.Join(d, "suse", "anchors", "adsiem-webblock.crt")
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

func TestFailedToolRunsAgainBestEffort(t *testing.T) {
	fakeTrust(t)
	lookPath = func(n string) (string, error) { return "/abs/" + n, nil }
	n := 0
	runTool = func(string, ...string) error { n++; return errors.New("boom") }
	ca, _ := newTestCA(t)
	if err := installTrust(ca.DER, ca.Fingerprint()); err == nil || n != 2 {
		t.Fatalf("err=%v runs=%d", err, n)
	}
}

func TestRunToolKillsHungGrandchild(t *testing.T) {
	script := filepath.Join(t.TempDir(), "tool.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 300 &\nwait\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := toolTimeout
	toolTimeout = 500 * time.Millisecond
	defer func() { toolTimeout = old }()
	start := time.Now()
	err := runTool(script)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("runTool blocked for %v", d)
	}
}

func TestSUSEAnchorUsedWhenItsDirExists(t *testing.T) {
	ran := fakeTrust(t)
	lookPath = func(n string) (string, error) {
		if n == "update-ca-certificates" {
			return "/abs/update-ca-certificates", nil
		}
		return "", errors.New("none")
	}
	if err := os.MkdirAll(filepath.Dir(suseAnchor), 0o755); err != nil {
		t.Fatal(err)
	}
	ca, _ := newTestCA(t)
	if err := installTrust(ca.DER, ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(suseAnchor); err != nil {
		t.Fatalf("SUSE anchor not written: %v", err)
	}
	if _, err := os.Stat(debianAnchor); err == nil {
		t.Fatal("Debian anchor written on SUSE")
	}
	if !trustInstalled(ca.Fingerprint()) {
		t.Fatal("SUSE anchor not seen as installed")
	}
	if err := removeTrust(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(suseAnchor); err == nil || len(*ran) != 2 {
		t.Fatalf("SUSE anchor not removed, ran=%v", *ran)
	}
}

func TestRemoveChecksDebianAndSUSEAnchors(t *testing.T) {
	fakeTrust(t)
	lookPath = func(n string) (string, error) { return "/abs/" + n, nil }
	for _, p := range []string{debianAnchor, suseAnchor} {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("x"), 0o644)
	}
	if err := removeTrust(""); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{debianAnchor, suseAnchor} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s left", p)
		}
	}
}
