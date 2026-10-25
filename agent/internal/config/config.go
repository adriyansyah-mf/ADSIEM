package config

import (
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

type DetectConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Rules           []string `yaml:"rules"`
	MaxBlocked      int      `yaml:"max_blocked"`
	MaxBlocksPerMin int      `yaml:"max_blocks_per_minute"`
}

type BufferConfig struct {
	SpillPath string `yaml:"spill_path"`
}

type LiveResponseConfig struct {
	// Refuse commands an operator approved on the server (the exec plugin);
	// artifacts still run.
	DisableCommands bool `yaml:"disable_commands"`
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
	Detect       DetectConfig       `yaml:"detect"`
	Buffer       BufferConfig       `yaml:"buffer"`
	Evidence     EvidenceConfig     `yaml:"evidence"`
	LiveResponse LiveResponseConfig `yaml:"live_response"`
	AntiTamper   AntiTamperConfig   `yaml:"anti_tamper"`
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
