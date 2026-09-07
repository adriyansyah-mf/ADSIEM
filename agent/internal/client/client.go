package client

import (
	"bytes"
	"crypto/tls"
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

// errRedirectRefused is returned via CheckRedirect (net/http then wraps it
// in a *url.Error) to stop the client following a redirect rather than
// silently downgrading a POST to a GET on it, which is Go's default
// behavior for a 301/302/303 response and would otherwise drop the request
// body -- and with it, the log/heartbeat payload -- without any error at
// all. Concretely this fires when BaseURL is configured for plain HTTP
// against a server that now redirects to HTTPS.
type errRedirectRefused struct {
	from, to string
}

func (e *errRedirectRefused) Error() string {
	return fmt.Sprintf("refusing to follow redirect (would drop request body): %s -> %s -- update server.url in config.yaml to the redirect target", e.from, e.to)
}

func refuseRedirect(req *http.Request, via []*http.Request) error {
	return &errRedirectRefused{from: via[len(via)-1].URL.String(), to: req.URL.String()}
}

// New builds a client for talking to the server. insecureSkipVerify disables
// TLS certificate verification -- only intended for bootstrapping trust with
// a self-signed server certificate; see ServerConfig.InsecureSkipVerify.
func New(baseURL, agentToken string, insecureSkipVerify bool) *Client {
	transport := http.DefaultTransport
	if insecureSkipVerify {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, documented bootstrap-only setting
		transport = t
	}
	return &Client{
		BaseURL:    baseURL,
		AgentToken: agentToken,
		httpClient: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     transport,
			CheckRedirect: refuseRedirect,
		},
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
