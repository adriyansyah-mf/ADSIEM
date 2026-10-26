package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type LogSource struct {
	Path    string `yaml:"path"`
	Type    string `yaml:"type"`
	Enabled bool   `yaml:"enabled"`
}

type AgentConfig struct {
	ID              string `yaml:"id"`
	Name            string `yaml:"name"`
	Group           string `yaml:"group"`
	Token           string `yaml:"token"`
	EnrollmentToken string `yaml:"enrollment_token"`
	BufferSize      int    `yaml:"buffer_size"`
	StateDir        string `yaml:"state_dir"`
	ConfigPath      string `yaml:"config_path"`
}

type ServerConfig struct {
	URL               string `yaml:"url"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"`
}

type FimConfig struct {
	Enabled    bool     `yaml:"enabled"`
	WatchPaths []string `yaml:"watch_paths"`
}

type FirewallConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Backend      string   `yaml:"backend"`
	DryRun       bool     `yaml:"dry_run"`
	ProtectedIPs []string `yaml:"protected_ips"`
	StatePath    string   `yaml:"state_path"`
}

type NetwatchConfig struct {
	Enabled          bool `yaml:"enabled"`
	SnapshotFallback bool `yaml:"snapshot_fallback"`
}

// ETWConfig controls the Windows ETW sensor (process, network and DNS
// telemetry without Sysmon). Mode: "auto" (default) runs it unless Sysmon is
// installed, so the same activity is not reported twice; "on" and "off".
type ETWConfig struct {
	Mode string `yaml:"mode"`
}

type DetectConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Rules           []string `yaml:"rules"`
	MaxBlocked      int      `yaml:"max_blocked"`
	MaxBlocksPerMin int      `yaml:"max_blocks_per_minute"`
}

// LinuxSensorConfig controls the eBPF file, kernel-module, ptrace,
// privilege, memfd and process-exit telemetry (internal/linsensor).
type LinuxSensorConfig struct {
	Disabled bool `yaml:"disabled"`
	// DisabledEvents switches off groups: file, module, ptrace,
	// privilege, memfd, exit. Fileless exec is always reported.
	DisabledEvents []string `yaml:"disabled_events"`
}

// RansomwareConfig controls canary files and the bulk-encryption
// heuristics (internal/ransomguard).
type RansomwareConfig struct {
	Disabled bool `yaml:"disabled"`
	// ReportOnly reports detections without stopping the process.
	ReportOnly bool `yaml:"report_only"`
	// Isolate also cuts the host off the network (firewall isolation) on
	// a canary hit or a confirmed detection.
	Isolate bool `yaml:"isolate"`
	// CanaryDirs (globs) and CanaryNames replace the defaults.
	CanaryDirs  []string `yaml:"canary_dirs"`
	CanaryNames []string `yaml:"canary_names"`
	// AllowImages are extra executable basenames the heuristics ignore.
	AllowImages []string `yaml:"allow_images"`
}

// YaraConfig controls on-access YARA scanning: new and changed files in
// risky directories are scanned with the rules the server distributes.
// With no rules on the server nothing is scanned.
type YaraConfig struct {
	// Disabled turns on-access scanning off; on-demand scans (tasks and
	// live response) still run.
	Disabled bool `yaml:"disabled"`
	// WatchPaths replaces the default directories; globs such as
	// C:\Users\*\Downloads are expanded every few minutes.
	WatchPaths []string `yaml:"watch_paths"`
	// MaxFileSizeMB skips larger files (default 32).
	MaxFileSizeMB int64 `yaml:"max_file_size_mb"`
}

// MemorySweepConfig controls the periodic search for writable and
// executable private memory in every process (internal/memscan).
type MemorySweepConfig struct {
	Disabled        bool `yaml:"disabled"`
	IntervalMinutes int  `yaml:"interval_minutes"` // default 5
}

type BufferConfig struct {
	SpillPath string `yaml:"spill_path"`
}

type LiveResponseConfig struct {
	// Refuse commands an operator approved on the server (the exec plugin);
	// artifacts still run.
	DisableCommands bool `yaml:"disable_commands"`
}

// PreventionConfig controls execution prevention (Linux): the server's
// execution rules, enforced by the BPF LSM or a fanotify helper.
type PreventionConfig struct {
	// Disabled stops enforcing and reporting execution rules on this host.
	Disabled bool `yaml:"disabled"`
}

type AntiTamperConfig struct {
	// Windows: the agent service is locked so only SYSTEM (the MSI, an
	// upgrade) can stop, reconfigure or delete it. true restores the default
	// permissions on the next start, e.g. to manage the service by hand.
	UnlockService bool `yaml:"unlock_service"`
}

type Config struct {
	Agent        AgentConfig        `yaml:"agent"`
	Server       ServerConfig       `yaml:"server"`
	Logs         []LogSource        `yaml:"logs"`
	FIM          FimConfig          `yaml:"fim"`
	Firewall     FirewallConfig     `yaml:"firewall"`
	Netwatch     NetwatchConfig     `yaml:"netwatch"`
	ETW          ETWConfig          `yaml:"etw"`
	Detect       DetectConfig       `yaml:"detect"`
	LinuxSensor  LinuxSensorConfig  `yaml:"linux_sensor"`
	Ransomware   RansomwareConfig   `yaml:"ransomware"`
	Yara         YaraConfig         `yaml:"yara"`
	MemorySweep  MemorySweepConfig  `yaml:"memory_sweep"`
	Buffer       BufferConfig       `yaml:"buffer"`
	Evidence     EvidenceConfig     `yaml:"evidence"`
	LiveResponse LiveResponseConfig `yaml:"live_response"`
	AntiTamper   AntiTamperConfig   `yaml:"anti_tamper"`
	Prevention   PreventionConfig   `yaml:"prevention"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Agent.BufferSize == 0 {
		cfg.Agent.BufferSize = 10000
	}
	if cfg.Server.HeartbeatInterval == 0 {
		cfg.Server.HeartbeatInterval = 30
	}
	if cfg.Firewall.Backend == "" {
		cfg.Firewall.Backend = "auto"
	}
	switch cfg.ETW.Mode {
	case "":
		cfg.ETW.Mode = "auto"
	case "auto", "on", "off":
	default:
		return nil, fmt.Errorf("etw.mode %q: use auto, on or off", cfg.ETW.Mode)
	}
	if err := cfg.defaultEvidence(); err != nil {
		return nil, err
	}
	if cfg.Agent.ConfigPath == "" {
		cfg.Agent.ConfigPath = path
	}
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
