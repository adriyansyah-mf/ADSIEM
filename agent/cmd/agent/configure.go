package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/siem-platform/agent/internal/config"
)

// configureOptions are the -configure flags; the Windows MSI passes its
// SERVER_URL / ENROLLMENT_KEY / AGENT_NAME / ENABLE_AUDITING properties here.
type configureOptions struct {
	server   string
	key      string
	name     string
	auditing string // "1"/"true"/"yes" to turn on the audit policy the decoders need (Windows)
}

// configure writes the server and enrollment key into the config file,
// creating it with the platform's default log sources when missing. A new key
// clears any previous enrollment, so the agent enrolls again with it.
func configure(configPath string, o configureOptions) error {
	o.server = strings.TrimRight(strings.TrimSpace(o.server), "/")
	o.key = strings.TrimSpace(o.key)
	o.name = strings.TrimSpace(o.name)

	cfg, err := config.Load(configPath)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		if o.server == "" || o.key == "" {
			return fmt.Errorf("%s doesn't exist yet: the first install needs a server URL and an enrollment key", configPath)
		}
		cfg = defaultConfig()
	default:
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	if o.server != "" {
		u, err := url.Parse(o.server)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("server %q is not an http(s)://host[:port] URL", o.server)
		}
		cfg.Server.URL = o.server
	}
	if o.key != "" {
		cfg.Agent.EnrollmentToken = o.key
		cfg.Agent.Token = ""
		cfg.Agent.ID = ""
	}
	if o.name != "" {
		cfg.Agent.Name = o.name
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		return err
	}
	if err := config.Save(configPath, cfg); err != nil {
		return err
	}
	if err := restrictConfigAccess(configPath); err != nil {
		return fmt.Errorf("restrict access to %s: %w", configPath, err)
	}
	switch strings.ToLower(strings.TrimSpace(o.auditing)) {
	case "1", "true", "yes":
		if err := enableAuditing(); err != nil {
			return fmt.Errorf("enable auditing: %w", err)
		}
	}
	return nil
}

func defaultConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Agent.Group = "default"
	cfg.Agent.BufferSize = 10000
	cfg.Server.HeartbeatInterval = 30
	cfg.Logs = defaultLogSources()
	return cfg
}
