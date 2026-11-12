package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Client is shared by every loop of the agent (heartbeat, senders, updater,
// flows, stores). Its token can change at runtime (rotation over the
// heartbeat), so it is read and set under a lock.
type Client struct {
	BaseURL    string
	httpClient *http.Client

	mu    sync.RWMutex
	token string
}

func New(baseURL, agentToken string) *Client {
	return &Client{
		BaseURL:    baseURL,
		token:      agentToken,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Token is the agent token sent as X-Agent-Token.
func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// SetToken replaces the token for every request from now on.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
}

func (c *Client) setToken(req *http.Request) {
	if t := c.Token(); t != "" {
		req.Header.Set("X-Agent-Token", t)
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
	c.setToken(req)
	return c.httpClient.Do(req)
}

// PostContext is Post bound to ctx instead of the client's 10s timeout — for
// long polls and live-response updates, which set their own deadline.
func (c *Client) PostContext(ctx context.Context, path string, payload any) (*http.Response, error) {
	return c.PostContextWith(ctx, path, payload, nil)
}

// PostContextWith is PostContext with extra request headers.
func (c *Client) PostContextWith(ctx context.Context, path string, payload any, headers map[string]string) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setToken(req)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}

// GetContext is a GET bound to ctx (no 10s cap): package downloads.
func (c *Client) GetContext(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	c.setToken(req)
	return http.DefaultClient.Do(req)
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
