package config

import (
	"encoding/json"
	"testing"
)

func mustUnmarshal(t *testing.T, s string, o *Overlay) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), o); err != nil {
		t.Fatal(err)
	}
}

func TestApplyOverlayNilKeepsLocal(t *testing.T) {
	cfg := &Config{FIM: FimConfig{Enabled: true}}
	if w := ApplyOverlay(cfg, nil); len(w) != 0 || !cfg.FIM.Enabled {
		t.Fatal(w, cfg.FIM)
	}
}

func TestApplyOverlayExplicitZeroOverrides(t *testing.T) {
	cfg := &Config{FIM: FimConfig{Enabled: true}, Yara: YaraConfig{WatchPaths: []string{`C:\x`}}}
	var o Overlay
	mustUnmarshal(t, `{"fim":{"enabled":false},"yara":{"watch_paths":[]}}`, &o)
	ApplyOverlay(cfg, &o)
	if cfg.FIM.Enabled || len(cfg.Yara.WatchPaths) != 0 {
		t.Fatal(cfg.FIM, cfg.Yara)
	}
}

func TestApplyOverlayURLSameHostOnly(t *testing.T) {
	cfg := &Config{Server: ServerConfig{URL: "https://Siem.example.com"}}
	var o Overlay
	mustUnmarshal(t, `{"server":{"url":"https://siem.example.com:8443/x"}}`, &o)
	if w := ApplyOverlay(cfg, &o); len(w) != 0 || cfg.Server.URL != "https://siem.example.com:8443/x" {
		t.Fatal(w, cfg.Server.URL)
	}
	mustUnmarshal(t, `{"server":{"url":"https://evil.example.net"}}`, &o)
	if w := ApplyOverlay(cfg, &o); len(w) != 1 || cfg.Server.URL != "https://siem.example.com:8443/x" {
		t.Fatal(w, cfg.Server.URL)
	}
}

func TestApplyOverlayURLRejectsNonHTTPS(t *testing.T) {
	cfg := &Config{Server: ServerConfig{URL: "https://siem.example.com"}}
	var o Overlay
	mustUnmarshal(t, `{"server":{"url":"http://siem.example.com"}}`, &o)
	if w := ApplyOverlay(cfg, &o); len(w) != 1 || cfg.Server.URL != "https://siem.example.com" {
		t.Fatal(w, cfg.Server.URL)
	}
}

func TestOverlayIgnoresUnlistedFields(t *testing.T) {
	cfg := &Config{AntiTamper: AntiTamperConfig{UnlockService: false}, Agent: AgentConfig{Token: "t"}}
	var o Overlay
	mustUnmarshal(t, `{"anti_tamper":{"unlock_service":true},"agent":{"token":"x","buffer_size":5}}`, &o)
	ApplyOverlay(cfg, &o)
	if cfg.AntiTamper.UnlockService || cfg.Agent.Token != "t" || cfg.Agent.BufferSize != 5 {
		t.Fatal(cfg)
	}
}

func TestApplyOverlayAllSections(t *testing.T) {
	cfg := &Config{}
	var o Overlay
	mustUnmarshal(t, `{
"server":{"heartbeat_interval":9},
"fim":{"enabled":true},
"firewall":{"enabled":true,"backend":"nft","dry_run":true,"protected_ips":["1.1.1.1"],"isolation_release_after_offline_minutes":-1},
"netwatch":{"enabled":true,"snapshot_fallback":true},
"etw":{"mode":"on","disabled_events":["file"]},
"detect":{"enabled":true,"rules":["a"],"max_blocked":3,"max_blocks_per_minute":4},
"linux_sensor":{"disabled":true,"disabled_events":["exit"]},
"ransomware":{"disabled":true,"canary_dirs":["d"],"canary_names":["n"],"canary_visible":true,"allow_images":["x.exe"],"report_only":true,"isolate":true},
"yara":{"watch_paths":["w"],"max_file_size_mb":7,"disabled":true},
"memory_sweep":{"disabled":true,"interval_minutes":2},
"evidence":{"enabled":true,"max_bytes":1,"segment_bytes":2,"reserved_bytes":3,"max_event_bytes":4,"dir":"/evil"},
"prevention":{"disabled":true},"notify":{"disabled":true},"project_scan":{"disabled":true},"update":{"disabled":true,"trusted_keys":["k"]}}`, &o)
	if w := ApplyOverlay(cfg, &o); len(w) != 0 {
		t.Fatal(w)
	}
	if cfg.Server.HeartbeatInterval != 9 || !cfg.FIM.Enabled ||
		cfg.Firewall.Backend != "nft" || !cfg.Firewall.DryRun || cfg.Firewall.ProtectedIPs[0] != "1.1.1.1" || cfg.Firewall.IsolationReleaseAfterOfflineMinutes != -1 ||
		!cfg.Netwatch.SnapshotFallback || cfg.ETW.Mode != "on" || cfg.ETW.DisabledEvents[0] != "file" ||
		cfg.Detect.MaxBlocked != 3 || cfg.Detect.MaxBlocksPerMin != 4 || cfg.Detect.Rules[0] != "a" ||
		!cfg.LinuxSensor.Disabled || cfg.LinuxSensor.DisabledEvents[0] != "exit" ||
		!cfg.Ransomware.Disabled || !cfg.Ransomware.CanaryVisible || cfg.Ransomware.AllowImages[0] != "x.exe" ||
		cfg.Yara.WatchPaths[0] != "w" || cfg.Yara.MaxFileSizeMB != 7 ||
		!cfg.MemorySweep.Disabled || cfg.MemorySweep.IntervalMinutes != 2 ||
		!cfg.Evidence.Enabled || cfg.Evidence.MaxBytes != 1 || cfg.Evidence.SegmentBytes != 2 || cfg.Evidence.ReservedBytes != 3 || cfg.Evidence.MaxEventBytes != 4 ||
		!cfg.Prevention.Disabled || !cfg.Notify.Disabled || !cfg.ProjectScan.Disabled || !cfg.Update.Disabled {
		t.Fatalf("%+v", cfg)
	}
	// Fields the spec keeps out of the overlay stay as they were.
	if cfg.Ransomware.ReportOnly || cfg.Ransomware.Isolate || len(cfg.Ransomware.CanaryDirs) != 0 || len(cfg.Ransomware.CanaryNames) != 0 ||
		cfg.Yara.Disabled || cfg.Evidence.Dir != "" || len(cfg.Update.TrustedKeys) != 0 {
		t.Fatalf("%+v", cfg)
	}
}

// Canary dirs and names are file paths the agent writes as SYSTEM/root: the
// server must not choose them, so an overlay carrying them changes nothing.
func TestApplyOverlayKeepsLocalCanaryPaths(t *testing.T) {
	cfg := &Config{Ransomware: RansomwareConfig{CanaryDirs: []string{`C:\local`}, CanaryNames: []string{"local.docx"}}}
	var o Overlay
	mustUnmarshal(t, `{"ransomware":{"canary_dirs":["C:\\Windows\\System32"],"canary_names":["evil.dll"],"canary_visible":true}}`, &o)
	ApplyOverlay(cfg, &o)
	if len(cfg.Ransomware.CanaryDirs) != 1 || cfg.Ransomware.CanaryDirs[0] != `C:\local` ||
		len(cfg.Ransomware.CanaryNames) != 1 || cfg.Ransomware.CanaryNames[0] != "local.docx" || !cfg.Ransomware.CanaryVisible {
		t.Fatalf("%+v", cfg.Ransomware)
	}
}
