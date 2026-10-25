package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDescribeNames(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][3]string{
		"siem-agent_1.9.0_amd64.deb":    {"1.9.0", "linux/amd64", "deb"},
		"siem-agent_1.9.0_arm64.deb":    {"1.9.0", "linux/arm64", "deb"},
		"siem-agent-1.9.0-1.x86_64.rpm": {"1.9.0", "linux/amd64", "rpm"},
		"siem-agent-1.9.0-x64.msi":      {"1.9.0", "windows/amd64", "msi"},
	}
	for name, want := range cases {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte("x"), 0o644)
		m, err := describe(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := [3]string{m.Version, m.OS + "/" + m.Arch, m.Format}; got != want || m.Size != 1 || m.File != name {
			t.Fatalf("%s: %+v", name, m)
		}
	}
	p := filepath.Join(dir, "siem-agent-windows-amd64-1.9.0.zip")
	_ = os.WriteFile(p, []byte("x"), 0o644)
	if _, err := describe(p); err == nil {
		t.Fatal("zip accepted: it has no installer to upgrade with")
	}
}

func TestSignVerifyAndTamper(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyFile := filepath.Join(dir, "k")
	_ = os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600)
	pkg := filepath.Join(dir, "siem-agent_2.0.0_amd64.deb")
	_ = os.WriteFile(pkg, []byte("fake deb"), 0o644)
	if err := sign([]string{"-key", keyFile, pkg}); err != nil {
		t.Fatal(err)
	}
	pubArg := base64.StdEncoding.EncodeToString(pub)
	if err := verify([]string{"-pub", pubArg, pkg}); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := verify([]string{"-pub", base64.StdEncoding.EncodeToString(other), pkg}); err == nil {
		t.Fatal("verified with an untrusted key")
	}
	_ = os.WriteFile(pkg, []byte("fake deb, replaced"), 0o644)
	if err := verify([]string{"-pub", pubArg, pkg}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("replaced file: %v", err)
	}
}
