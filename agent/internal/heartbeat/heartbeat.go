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

type AgentTask struct {
	ID       string         `json:"id"`
	TaskType string         `json:"task_type"`
	Params   map[string]any `json:"params"`
}

// CustomComplianceRule is an analyst-authored SCA rule (see internal/sca's
// rule DSL) scoped to this agent's endpoint — the automated counterpart to
// a manually-attested custom compliance control. The agent evaluates these
// locally every hygiene cycle exactly like its built-in policy checks.
type CustomComplianceRule struct {
	ID        string   `json:"id"`
	Rules     []string `json:"rules"`
	Condition string   `json:"condition"`
}

type HeartbeatRequest struct {
	AgentID       string `json:"agent_id"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	BufferDropped int64  `json:"buffer_dropped"`
	// P0-B fleet-health telemetry (AGENT_PRODUCTION_IMPROVEMENT_ROADMAP.md).
	BufferDepth                   int   `json:"buffer_depth"`
	OldestBufferedEventAgeSeconds *int  `json:"oldest_buffered_event_age_seconds"`
	UptimeSeconds                 int64 `json:"uptime_seconds"`
}

type HeartbeatResponse struct {
	ConfigHash            string                 `json:"config_hash"`
	LogSources            []LogSource            `json:"log_sources"`
	FimPaths              []string               `json:"fim_paths"`
	Tasks                 []AgentTask            `json:"tasks"`
	CustomComplianceRules []CustomComplianceRule `json:"custom_compliance_rules"`
}

// Loop sends heartbeats every interval.
// Calls onConfig when config hash changes, calls onTasks for every heartbeat with tasks.
func Loop(
	cfg *config.Config,
	buf *buffer.Buffer,
	c *client.Client,
	startedAt time.Time,
	version string,
	onConfig func(HeartbeatResponse),
	onTasks func([]AgentTask),
) {
	lastHash := ""
	interval := time.Duration(cfg.Server.HeartbeatInterval) * time.Second

	for {
		dropped := buf.ResetDropped()
		depth, _, _ := buf.Stats()

		var oldestAgeSeconds *int
		if age, ok := buf.OldestAge(); ok {
			s := int(age.Seconds())
			oldestAgeSeconds = &s
		}

		payload := HeartbeatRequest{
			AgentID:                       cfg.Agent.ID,
			Status:                        "online",
			Version:                       version,
			BufferDropped:                 dropped,
			BufferDepth:                   depth,
			OldestBufferedEventAgeSeconds: oldestAgeSeconds,
			UptimeSeconds:                 int64(time.Since(startedAt).Seconds()),
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
