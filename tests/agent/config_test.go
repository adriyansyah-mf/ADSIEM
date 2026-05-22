package agent_test

import (
	"os"
	"testing"

	"github.com/siem-platform/agent/internal/config"
)

func TestLoadConfig(t *testing.T) {
	content := `
agent:
  id: test-001
  name: test
  group: prod
  token: "tok"
  buffer_size: 5000
server:
  url: http://localhost:8000
  heartbeat_interval: 15
logs:
  - path: /var/log/auth.log
    type: linux_auth
`
	f, _ := os.CreateTemp("", "config-*.yaml")
	f.WriteString(content)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := config.Load(f.Name())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Agent.ID != "test-001" {
		t.Errorf("expected agent id test-001, got %s", cfg.Agent.ID)
	}
	if cfg.Agent.BufferSize != 5000 {
		t.Errorf("expected buffer_size 5000, got %d", cfg.Agent.BufferSize)
	}
	if len(cfg.Logs) != 1 {
		t.Errorf("expected 1 log source, got %d", len(cfg.Logs))
	}
}

func TestLoadDefaultsWhenZero(t *testing.T) {
	content := "agent:\n  id: x\nserver:\n  url: http://x\n"
	f, _ := os.CreateTemp("", "config-*.yaml")
	f.WriteString(content)
	f.Close()
	defer os.Remove(f.Name())

	cfg, _ := config.Load(f.Name())
	if cfg.Agent.BufferSize != 10000 {
		t.Errorf("expected default buffer_size 10000, got %d", cfg.Agent.BufferSize)
	}
	if cfg.Server.HeartbeatInterval != 30 {
		t.Errorf("expected default heartbeat_interval 30, got %d", cfg.Server.HeartbeatInterval)
	}
}
