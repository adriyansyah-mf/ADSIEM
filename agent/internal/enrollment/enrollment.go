package enrollment

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
)

type LogSourcePayload struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Enabled bool   `json:"is_enabled"`
}

type EnrollRequest struct {
	EnrollmentToken string             `json:"enrollment_token"`
	Hostname        string             `json:"hostname"`
	Version         string             `json:"version"`
	Group           string             `json:"group"`
	Name            string             `json:"name"`
	LogSources      []LogSourcePayload `json:"log_sources"`
}

type EnrollResponse struct {
	AgentID    string `json:"agent_id"`
	AgentToken string `json:"agent_token"`
}

// Enroll performs first-run enrollment. Retries indefinitely on network errors.
func Enroll(cfg *config.Config, configPath, enrollToken string) error {
	slog.Info("enrolling agent", "server", cfg.Server.URL, "name", cfg.Agent.Name)
	c := client.New(cfg.Server.URL, "")

	sources := make([]LogSourcePayload, len(cfg.Logs))
	for i, l := range cfg.Logs {
		sources[i] = LogSourcePayload{Path: l.Path, Type: l.Type, Enabled: true}
	}
	h, _ := os.Hostname()
	payload := EnrollRequest{
		EnrollmentToken: enrollToken,
		Hostname:        h,
		Version:         "1.0.0",
		Group:           cfg.Agent.Group,
		Name:            cfg.Agent.Name,
		LogSources:      sources,
	}

	backoff := 2 * time.Second
	for {
		resp, err := c.Post("/api/agent/enroll", payload)
		if err != nil {
			slog.Error("enroll request failed", "err", err, "retry_in", backoff)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 201 {
			return fmt.Errorf("enrollment rejected (status %d): %s", resp.StatusCode, body)
		}
		var result EnrollResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("decode enroll response: %w", err)
		}
		cfg.Agent.Token = result.AgentToken
		if err := config.Save(configPath, cfg); err != nil {
			return fmt.Errorf("save config after enroll: %w", err)
		}
		slog.Info("enrollment successful", "agent_id", result.AgentID)
		return nil
	}
}
