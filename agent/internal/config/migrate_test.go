package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Configs written by installers before 1.22.2 carry "firewall: enabled: false"
// that nobody chose; Migrate turns enforcement on once.
func TestMigrateEnablesFirewallFromOldInstaller(t *testing.T) {
	cfg := &Config{}
	changed := Migrate(cfg)
	if !cfg.Firewall.Enabled || cfg.Version != CurrentVersion || cfg.Firewall.Backend != "auto" {
		t.Fatalf("not migrated: %+v version %d", cfg.Firewall, cfg.Version)
	}
	if len(changed) == 0 || !strings.Contains(strings.Join(changed, ","), "firewall.enabled") {
		t.Fatalf("changes not reported: %v", changed)
	}
	if again := Migrate(cfg); len(again) != 0 {
		t.Fatalf("second run must be a no-op, got %v", again)
	}
}

// Packaged Linux configs before 1.27.0 had no netwatch section: network
// telemetry was off on every install. Version 2 turns it on, once, on Linux.
func TestMigrateEnablesNetwatchOnLinuxOnce(t *testing.T) {
	cfg := &Config{Version: 1}
	changed := migrate(cfg, "linux")
	if !cfg.Netwatch.Enabled || !cfg.Netwatch.SnapshotFallback || cfg.Version != 2 {
		t.Fatalf("netwatch not turned on: %+v version %d", cfg.Netwatch, cfg.Version)
	}
	if !strings.Contains(strings.Join(changed, ","), "netwatch.enabled") {
		t.Fatalf("change not reported: %v", changed)
	}
	// an operator turning it off afterwards is respected
	cfg.Netwatch.Enabled = false
	if again := migrate(cfg, "linux"); len(again) != 0 || cfg.Netwatch.Enabled {
		t.Fatalf("a version 2 config must stay as written: %v %+v", again, cfg.Netwatch)
	}
	// Windows has ETW network telemetry: nothing to turn on
	win := &Config{Version: 1}
	migrate(win, "windows")
	if win.Netwatch.Enabled || win.Version != 2 {
		t.Fatalf("windows: %+v version %d", win.Netwatch, win.Version)
	}
	// a config that already had it on keeps its own fallback choice
	on := &Config{Version: 1, Netwatch: NetwatchConfig{Enabled: true}}
	migrate(on, "linux")
	if on.Netwatch.SnapshotFallback {
		t.Fatal("an explicit netwatch section must not be rewritten")
	}
}

func TestMigrateKeepsDryRunAndLaterChoices(t *testing.T) {
	dry := &Config{}
	dry.Firewall.DryRun = true
	Migrate(dry)
	if dry.Firewall.Enabled {
		t.Fatal("dry-run config must not be switched to enforcing")
	}

	// Disabled again after the migration: the operator's choice, kept.
	off := &Config{Version: CurrentVersion}
	if changed := Migrate(off); len(changed) != 0 || off.Firewall.Enabled {
		t.Fatalf("current config must be left alone: %v %+v", changed, off.Firewall)
	}
}

func TestPackagedTemplatesEnableFirewall(t *testing.T) {
	for _, template := range []string{"../../packaging/config.yaml", "../../packaging/windows/config.yaml"} {
		t.Run(template, func(t *testing.T) {
			b, err := os.ReadFile(template)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := strings.Replace(string(b), "agent:\n", "agent:\n  state_dir: "+quote(t.TempDir())+"\n", 1)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.Firewall.Enabled || cfg.Version != CurrentVersion {
				t.Fatalf("template must ship an enforcing firewall: %+v version %d", cfg.Firewall, cfg.Version)
			}
			if changed := Migrate(cfg); len(changed) != 0 {
				t.Fatalf("a fresh template needs no migration, got %v", changed)
			}
		})
	}
}
