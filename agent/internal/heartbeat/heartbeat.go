package heartbeat

import (
	"encoding/json"
	"io"
	"log/slog"
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

type HeartbeatRequest struct {
	AgentID       string `json:"agent_id"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	BufferDropped int64  `json:"buffer_dropped"`
}

type HeartbeatResponse struct {
	ConfigHash string      `json:"config_hash"`
	LogSources []LogSource `json:"log_sources"`
}

// Loop sends heartbeats every interval seconds.
// On config hash change it calls onSourcesChanged with the new sources.
func Loop(
	cfg *config.Config,
	buf *buffer.Buffer,
	c *client.Client,
	onSourcesChanged func([]LogSource),
) {
	lastHash := ""
	interval := time.Duration(cfg.Server.HeartbeatInterval) * time.Second

	for {
		dropped := buf.ResetDropped()
		payload := HeartbeatRequest{
			AgentID:       cfg.Agent.ID,
			Status:        "online",
			Version:       "1.0.0",
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
					slog.Info("log sources updated", "hash", hbResp.ConfigHash)
					lastHash = hbResp.ConfigHash
					onSourcesChanged(hbResp.LogSources)
				}
			}
		} else {
			slog.Warn("heartbeat non-200", "status", resp.StatusCode)
		}
		time.Sleep(interval)
	}
}
