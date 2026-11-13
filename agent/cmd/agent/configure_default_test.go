package main

import (
	"runtime"
	"testing"

	"github.com/siem-platform/agent/internal/config"
)

// The config -configure writes when there is none (the Windows MSI, a Linux
// host whose config was removed) must match the packaged templates: it is at
// CurrentVersion, so Migrate never adds what it lacks later.
func TestDefaultConfigMatchesThePackagedTemplates(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Version != config.CurrentVersion || !cfg.Firewall.Enabled {
		t.Fatalf("version %d firewall %+v", cfg.Version, cfg.Firewall)
	}
	switch runtime.GOOS {
	case "linux":
		if !cfg.Netwatch.Enabled || !cfg.Netwatch.SnapshotFallback {
			t.Fatalf("linux default must enable netwatch: %+v", cfg.Netwatch)
		}
	case "windows":
		found := false
		for _, l := range cfg.Logs {
			found = found || (l.Path == "eventlog:Microsoft-Windows-CodeIntegrity/Operational" && l.Type == "windows_codeintegrity")
		}
		if !found {
			t.Fatalf("windows default must collect CodeIntegrity/Operational: %+v", cfg.Logs)
		}
		if cfg.Netwatch.Enabled {
			t.Fatal("netwatch is Linux only")
		}
	}
}
