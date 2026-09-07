package sca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHDDirectiveLookup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("PermitRootLogin no\nMaxAuthTries 4\n"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg, err := loadSSHDConfigFrom(path)
	if err != nil {
		t.Fatalf("loadSSHDConfigFrom: %v", err)
	}
	if cfg["permitrootlogin"] != "no" {
		t.Fatalf("expected permitrootlogin=no, got %q", cfg["permitrootlogin"])
	}
	if cfg["maxauthtries"] != "4" {
		t.Fatalf("expected maxauthtries=4, got %q", cfg["maxauthtries"])
	}
}

func TestSSHDFollowsIncludeDirective(t *testing.T) {
	dir := t.TempDir()
	// An absolute Include glob bypasses the package's fixed sshdConfigDir
	// resolution entirely, so this test doesn't depend on /etc/ssh existing.
	dropin := filepath.Join(dir, "10-hardening.conf")
	if err := os.WriteFile(dropin, []byte("PermitRootLogin no\n"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	main := filepath.Join(dir, "sshd_config")
	mainContent := "Include " + filepath.Join(dir, "*.conf") + "\nPermitRootLogin yes\n"
	if err := os.WriteFile(main, []byte(mainContent), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	result := make(map[string]string)
	parseSSHDConfigInto(main, result)

	if result["permitrootlogin"] != "no" {
		t.Fatalf("expected Include'd value (first occurrence wins), got %q", result["permitrootlogin"])
	}
}

func TestSSHDMissingFile(t *testing.T) {
	if _, err := loadSSHDConfigFrom("/nonexistent/sshd_config"); err == nil {
		t.Fatal("expected error for missing sshd_config")
	}
}
