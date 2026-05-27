package heartbeat

import (
	"encoding/json"
	"io"
	"log/slog"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/version"
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
	AgentID       string `json:"agent_id"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	BufferDropped int64  `json:"buffer_dropped"`
}

type HeartbeatResponse struct {
	ConfigHash string      `json:"config_hash"`
	LogSources []LogSource `json:"log_sources"`
	FimPaths   []string    `json:"fim_paths"`
	Tasks      []AgentTask `json:"tasks"`
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

	for {
		dropped := buf.ResetDropped()
		payload := HeartbeatRequest{
			AgentID:       cfg.Agent.ID,
			Status:        "online",
			Version:       version.Version,
			BufferDropped: dropped,
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
		} else if resp.StatusCode == 401 {
			slog.Error("heartbeat rejected: agent token invalid or agent not found — check config token or re-enroll", "status", 401)
		} else {
			slog.Warn("heartbeat non-200", "status", resp.StatusCode)
		}
		time.Sleep(interval)
	}
}
