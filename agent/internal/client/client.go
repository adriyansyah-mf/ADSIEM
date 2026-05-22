package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type Client struct {
	BaseURL    string
	AgentToken string
	httpClient *http.Client
}

func New(baseURL, agentToken string) *Client {
	return &Client{
		BaseURL:    baseURL,
		AgentToken: agentToken,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Post(path string, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return c.PostRaw(path, bytes.NewReader(body))
}

func (c *Client) PostRaw(path string, body *bytes.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", c.BaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.AgentToken != "" {
		req.Header.Set("X-Agent-Token", c.AgentToken)
	}
	return c.httpClient.Do(req)
}

// PostWithRetry retries up to maxAttempts with exponential backoff.
func (c *Client) PostWithRetry(path string, payload any, maxAttempts int) error {
	backoff := time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := c.Post(path, payload)
		if err == nil && resp.StatusCode < 500 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		if attempt == maxAttempts {
			return fmt.Errorf("all %d attempts failed", maxAttempts)
		}
		slog.Warn("request failed, retrying", "path", path, "attempt", attempt, "backoff", backoff)
		time.Sleep(backoff)
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
	return nil
}
