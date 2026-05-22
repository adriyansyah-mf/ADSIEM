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
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Group      string `yaml:"group"`
	Token      string `yaml:"token"`
	BufferSize int    `yaml:"buffer_size"`
}

type ServerConfig struct {
	URL               string `yaml:"url"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"`
}

type FimConfig struct {
	Enabled    bool     `yaml:"enabled"`
	WatchPaths []string `yaml:"watch_paths"`
}

type Config struct {
	Agent  AgentConfig  `yaml:"agent"`
	Server ServerConfig `yaml:"server"`
	Logs   []LogSource  `yaml:"logs"`
	FIM    FimConfig    `yaml:"fim"`
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
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
