package heartbeat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
)

type LogSource struct {
	Path      string `json:"path"`
	LogType   string `json:"log_type"`
	IsEnabled bool   `json:"is_enabled"`
}

type AgentTask struct {
	ID       string         `json:"id"`
	TaskType string         `json:"task_type"`
	Params   map[string]any `json:"params"`
}

type HeartbeatRequest struct {
	AgentID       string     `json:"agent_id"`
	Status        string     `json:"status"`
	Version       string     `json:"version"`
	BufferDropped int64      `json:"buffer_dropped"`
	Reason        string     `json:"reason,omitempty"` // with status "stopping": service_stop | system_shutdown
	Integrity     *Integrity `json:"integrity,omitempty"`
}

// Integrity is what the server compares against the agent's baseline: a
// binary or config that changes without a version change is tampering.
type Integrity struct {
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
}

type FirewallRule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr"`
	Proto      string `json:"proto"`
	Port       int    `json:"port"`
	Direction  string `json:"direction"`
	TTLSeconds int    `json:"ttl_seconds"`
	Reason     string `json:"reason"`
}

// AgentVersion is sent on every heartbeat; main sets it from its -ldflags
// version. The server uses it to tell which agents support live-response flows.
var AgentVersion = "dev"

// ConfigPath is the config file whose hash goes in each heartbeat; main sets it.
var ConfigPath string

// integrityEvery: hashing reads the whole binary, so not on every beat.
const integrityEvery = 5 * time.Minute

func sha256File(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func currentIntegrity() *Integrity {
	exe, err := os.Executable()
	if err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
	}
	in := Integrity{ConfigSHA256: sha256File(ConfigPath)}
	if err == nil {
		in.BinarySHA256 = sha256File(exe)
	}
	if in == (Integrity{}) {
		return nil
	}
	return &in
}

// SendStopping tells the server this agent is stopping on purpose, so it can
// tell a stopped service (alert) from a host shutting down or a lost network.
func SendStopping(cfg *config.Config, c *client.Client, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.PostContext(ctx, "/api/ingest/heartbeat", HeartbeatRequest{
		AgentID: cfg.Agent.ID, Status: "stopping", Version: AgentVersion, Reason: reason,
	})
	if err != nil {
		slog.Warn("could not report stopping", "err", err)
		return
	}
	resp.Body.Close()
}

type HeartbeatResponse struct {
	ConfigHash string         `json:"config_hash"`
	LogSources []LogSource    `json:"log_sources"`
	FimPaths   []string       `json:"fim_paths"`
	Tasks      []AgentTask    `json:"tasks"`
	Firewall   []FirewallRule `json:"firewall"`
}

// Loop sends heartbeats every interval.
// Calls onConfig when config hash changes, calls onTasks for every heartbeat with tasks.
func Loop(
	cfg *config.Config,
	buf *buffer.Buffer,
	c *client.Client,
	onConfig func(HeartbeatResponse),
	onTasks func([]AgentTask),
) {
	lastHash := ""
	interval := time.Duration(cfg.Server.HeartbeatInterval) * time.Second
	var integrity *Integrity
	var hashedAt time.Time

	for {
		if integrity == nil || time.Since(hashedAt) >= integrityEvery {
			integrity, hashedAt = currentIntegrity(), time.Now()
		}
		dropped := buf.ResetDropped()
		payload := HeartbeatRequest{
			AgentID:       cfg.Agent.ID,
			Status:        "online",
			Version:       AgentVersion,
			BufferDropped: dropped,
			Integrity:     integrity,
		}
		resp, err := c.Post("/api/ingest/heartbeat", payload)
		if err != nil {
			slog.Error("heartbeat failed", "err", err)
			time.Sleep(interval)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			var hbResp HeartbeatResponse
			if err := json.Unmarshal(body, &hbResp); err == nil {
				if hbResp.ConfigHash != lastHash {
					slog.Info("config updated", "hash", hbResp.ConfigHash)
					lastHash = hbResp.ConfigHash
					onConfig(hbResp)
				}
				if len(hbResp.Tasks) > 0 {
					slog.Info("tasks received", "count", len(hbResp.Tasks))
					onTasks(hbResp.Tasks)
				}
			}
		} else {
			slog.Warn("heartbeat non-200", "status", resp.StatusCode)
		}
		time.Sleep(interval)
	}
}
