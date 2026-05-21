# SIEM Platform — Plan 3: Go Agent

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Go agent that enrolls with the server, tails log files, ships logs via HTTP, manages a ring buffer for offline queuing, hot-reloads log sources from server heartbeat responses, and watches config.yaml with fsnotify.

**Architecture:** One goroutine per log source (tailer), one sender loop draining a shared ring buffer, one heartbeat loop that receives updated log sources from the server and signals the tailer manager to add/remove goroutines. Graceful shutdown on SIGTERM/SIGINT.

**Tech Stack:** Go 1.22+, github.com/fsnotify/fsnotify, gopkg.in/yaml.v3, log/slog (stdlib), net/http (stdlib)

**Prerequisite:** Plan 1 must be complete. server-api must be running and reachable.

---

## File Map

```
agent/
├── Dockerfile
├── go.mod
├── go.sum
├── config.yaml
├── cmd/
│   └── agent/
│       └── main.go              — wires all packages, signal handler
└── internal/
    ├── config/
    │   ├── config.go            — YAML config struct + loader
    │   └── watcher.go          — fsnotify watcher for config.yaml
    ├── buffer/
    │   └── buffer.go           — thread-safe ring buffer
    ├── client/
    │   └── client.go           — HTTP client with retry/backoff
    ├── enrollment/
    │   └── enrollment.go       — first-run enrollment flow
    ├── heartbeat/
    │   └── heartbeat.go        — heartbeat loop + config sync
    └── tailer/
        ├── tailer.go           — single log file tail goroutine
        └── manager.go          — manages set of active tailers

tests/agent/
├── buffer_test.go
└── config_test.go
```

---

## Task 1: Go Module & Config

**Files:**
- Create: `agent/go.mod`
- Create: `agent/config.yaml`
- Create: `agent/internal/config/config.go`
- Create: `agent/internal/config/watcher.go`

- [ ] **Step 1: Initialize go module**

```bash
mkdir -p agent/cmd/agent agent/internal/{config,buffer,client,enrollment,heartbeat,tailer}
mkdir -p tests/agent
cd agent
go mod init github.com/siem-platform/agent
go get github.com/fsnotify/fsnotify@v1.7.0
go get gopkg.in/yaml.v3@v3.0.1
```

- [ ] **Step 2: Write config.yaml**

```yaml
agent:
  id: agent-demo
  name: demo-agent
  group: default
  token: ""
  buffer_size: 10000

server:
  url: http://server-api:8000
  heartbeat_interval: 30

logs:
  - path: /host/var/log/auth.log
    type: linux_auth
  - path: /host/var/log/syslog
    type: syslog
```

- [ ] **Step 3: Write config.go**

```go
// agent/internal/config/config.go
package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type LogSource struct {
	Path    string `yaml:"path"`
	Type    string `yaml:"type"`
	Enabled bool   `yaml:"enabled"`
}

type AgentConfig struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Group      string `yaml:"group"`
	Token      string `yaml:"token"`
	BufferSize int    `yaml:"buffer_size"`
}

type ServerConfig struct {
	URL               string `yaml:"url"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"`
}

type Config struct {
	Agent  AgentConfig  `yaml:"agent"`
	Server ServerConfig `yaml:"server"`
	Logs   []LogSource  `yaml:"logs"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Agent.BufferSize == 0 {
		cfg.Agent.BufferSize = 10000
	}
	if cfg.Server.HeartbeatInterval == 0 {
		cfg.Server.HeartbeatInterval = 30
	}
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
```

- [ ] **Step 4: Write watcher.go**

```go
// agent/internal/config/watcher.go
package config

import (
	"log/slog"
	"github.com/fsnotify/fsnotify"
)

// Watch calls onChange whenever the file at path is modified.
// Only reloads Agent.Name, Agent.Group, Server.URL — log sources
// are managed by the server after enrollment.
func Watch(path string, onChange func(newCfg *Config)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return err
	}
	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					cfg, err := Load(path)
					if err != nil {
						slog.Error("config reload failed", "err", err)
						continue
					}
					slog.Info("config reloaded", "path", path)
					onChange(cfg)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("fsnotify error", "err", err)
			}
		}
	}()
	return nil
}
```

- [ ] **Step 5: Write config test**

```go
// tests/agent/config_test.go
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
```

- [ ] **Step 6: Run tests**

```bash
cd agent
go test ./... -run TestLoad -v
```

Expected: 2 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add agent/
git commit -m "feat: add Go agent config package with YAML loader and fsnotify watcher"
```

---

## Task 2: Ring Buffer

**Files:**
- Create: `agent/internal/buffer/buffer.go`
- Create: `tests/agent/buffer_test.go`

- [ ] **Step 1: Write failing test**

```go
// tests/agent/buffer_test.go
package agent_test

import (
	"testing"
	"github.com/siem-platform/agent/internal/buffer"
)

func TestBufferPushPop(t *testing.T) {
	b := buffer.New(3)
	b.Push("a")
	b.Push("b")
	item, ok := b.Pop()
	if !ok || item != "a" {
		t.Errorf("expected 'a', got %v (ok=%v)", item, ok)
	}
}

func TestBufferDropsOldestWhenFull(t *testing.T) {
	b := buffer.New(2)
	b.Push("a")
	b.Push("b")
	b.Push("c") // should drop "a"
	if b.Dropped() != 1 {
		t.Errorf("expected 1 dropped, got %d", b.Dropped())
	}
	item, _ := b.Pop()
	if item != "b" {
		t.Errorf("expected 'b' after drop, got %v", item)
	}
}

func TestBufferEmptyPop(t *testing.T) {
	b := buffer.New(5)
	_, ok := b.Pop()
	if ok {
		t.Error("expected ok=false on empty pop")
	}
}

func TestBufferLen(t *testing.T) {
	b := buffer.New(10)
	b.Push("x")
	b.Push("y")
	if b.Len() != 2 {
		t.Errorf("expected len 2, got %d", b.Len())
	}
}
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
go test ./... -run TestBuffer 2>&1 | head -5
```

Expected: build error — `buffer` package not found.

- [ ] **Step 3: Write buffer.go**

```go
// agent/internal/buffer/buffer.go
package buffer

import "sync"

type Buffer struct {
	mu      sync.Mutex
	items   []string
	cap     int
	dropped int64
}

func New(capacity int) *Buffer {
	return &Buffer{items: make([]string, 0, capacity), cap: capacity}
}

func (b *Buffer) Push(item string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) >= b.cap {
		b.items = b.items[1:] // drop oldest
		b.dropped++
	}
	b.items = append(b.items, item)
}

func (b *Buffer) Pop() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return "", false
	}
	item := b.items[0]
	b.items = b.items[1:]
	return item, true
}

func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

func (b *Buffer) Dropped() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

func (b *Buffer) ResetDropped() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.dropped
	b.dropped = 0
	return d
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./... -run TestBuffer -v
```

Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/internal/buffer/ tests/agent/buffer_test.go
git commit -m "feat: add thread-safe ring buffer with drop-oldest semantics"
```

---

## Task 3: HTTP Client

**Files:**
- Create: `agent/internal/client/client.go`

- [ ] **Step 1: Write client.go**

```go
// agent/internal/client/client.go
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
	req, err := http.NewRequest("POST", c.BaseURL+path, bytes.NewReader(body))
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
		backoff = min(backoff*2, 60*time.Second)
	}
	return nil
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
```

- [ ] **Step 2: Commit**

```bash
git add agent/internal/client/
git commit -m "feat: add HTTP client with retry and exponential backoff"
```

---

## Task 4: Enrollment

**Files:**
- Create: `agent/internal/enrollment/enrollment.go`

- [ ] **Step 1: Write enrollment.go**

```go
// agent/internal/enrollment/enrollment.go
package enrollment

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

const enrollmentToken = "bootstrap-token" // read from env in main

// Enroll performs first-run enrollment and saves the agent token to config.
// Blocks until enrollment succeeds, retrying indefinitely.
func Enroll(cfg *config.Config, configPath, enrollToken string) error {
	slog.Info("enrolling agent", "server", cfg.Server.URL)

	c := client.New(cfg.Server.URL, "")
	sources := make([]LogSourcePayload, len(cfg.Logs))
	for i, l := range cfg.Logs {
		sources[i] = LogSourcePayload{Path: l.Path, Type: l.Type, Enabled: true}
	}

	payload := EnrollRequest{
		EnrollmentToken: enrollToken,
		Hostname:        hostname(),
		Version:         "1.0.0",
		Group:           cfg.Agent.Group,
		Name:            cfg.Agent.Name,
		LogSources:      sources,
	}

	backoff := 2 * time.Second
	for {
		resp, err := c.Post("/api/agent/enroll", payload)
		if err != nil {
			slog.Error("enroll request failed", "err", err, "retrying_in", backoff)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 201 {
			body, _ := io.ReadAll(resp.Body)
			slog.Error("enroll rejected", "status", resp.StatusCode, "body", string(body))
			return fmt.Errorf("enrollment rejected: %d", resp.StatusCode)
		}
		var result EnrollResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decode enroll response: %w", err)
		}
		cfg.Agent.Token = result.AgentToken
		if err := config.Save(configPath, cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		slog.Info("enrollment successful", "agent_id", result.AgentID)
		return nil
	}
}

func hostname() string {
	import_os_hostname := func() string {
		h, _ := import_os()
		return h
	}
	return import_os_hostname()
}

func import_os() (string, error) {
	import "os"
	return os.Hostname()
}
```

Wait — Go doesn't support inline imports. Fix `enrollment.go` to use the `os` package correctly:

- [ ] **Step 2: Write correct enrollment.go**

```go
// agent/internal/enrollment/enrollment.go
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
```

- [ ] **Step 3: Compile check**

```bash
cd agent && go build ./...
```

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add agent/internal/enrollment/
git commit -m "feat: add agent enrollment with retry and config save"
```

---

## Task 5: Heartbeat

**Files:**
- Create: `agent/internal/heartbeat/heartbeat.go`

- [ ] **Step 1: Write heartbeat.go**

```go
// agent/internal/heartbeat/heartbeat.go
package heartbeat

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
```

- [ ] **Step 2: Commit**

```bash
git add agent/internal/heartbeat/
git commit -m "feat: add heartbeat loop with server config sync"
```

---

## Task 6: Log Tailer

**Files:**
- Create: `agent/internal/tailer/tailer.go`
- Create: `agent/internal/tailer/manager.go`

- [ ] **Step 1: Write tailer.go**

```go
// agent/internal/tailer/tailer.go
package tailer

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
)

type LogEntry struct {
	LogType    string
	RawMessage string
}

// Tail reads new lines from path and pushes them to buf.
// Seeks to end of file on first open (tail -f behavior).
// Retries if file is not found (handles log rotation).
// Stops when ctx is cancelled via stopCh.
func Tail(path, logType string, buf *buffer.Buffer, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			slog.Warn("cannot open log file", "path", path, "err", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			time.Sleep(time.Second)
			continue
		}
		slog.Info("tailing", "path", path, "type", logType)
		scanner := bufio.NewScanner(f)
		for {
			select {
			case <-stopCh:
				f.Close()
				return
			default:
			}
			if scanner.Scan() {
				line := scanner.Text()
				if line != "" {
					buf.Push(encode(logType, line))
				}
			} else {
				if scanner.Err() != nil {
					slog.Error("scanner error", "path", path, "err", scanner.Err())
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		f.Close()
	}
}

func encode(logType, rawMessage string) string {
	return logType + "\x00" + rawMessage
}

func Decode(entry string) (logType, rawMessage string) {
	for i, c := range entry {
		if c == '\x00' {
			return entry[:i], entry[i+1:]
		}
	}
	return "unknown", entry
}
```

- [ ] **Step 2: Write manager.go**

```go
// agent/internal/tailer/manager.go
package tailer

import (
	"log/slog"
	"sync"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/heartbeat"
)

type source struct {
	path    string
	logType string
	stopCh  chan struct{}
}

// Manager maintains a set of active tailers and hot-reloads on source changes.
type Manager struct {
	mu      sync.Mutex
	buf     *buffer.Buffer
	sources map[string]*source // key = path
}

func NewManager(buf *buffer.Buffer) *Manager {
	return &Manager{buf: buf, sources: make(map[string]*source)}
}

// Update starts/stops tailers to match the given sources list.
func (m *Manager) Update(sources []heartbeat.LogSource) {
	m.mu.Lock()
	defer m.mu.Unlock()

	wanted := make(map[string]heartbeat.LogSource)
	for _, s := range sources {
		if s.IsEnabled {
			wanted[s.Path] = s
		}
	}

	// Stop removed sources
	for path, active := range m.sources {
		if _, ok := wanted[path]; !ok {
			slog.Info("stopping tailer", "path", path)
			close(active.stopCh)
			delete(m.sources, path)
		}
	}

	// Start new sources
	for path, s := range wanted {
		if _, exists := m.sources[path]; !exists {
			slog.Info("starting tailer", "path", path, "type", s.LogType)
			stopCh := make(chan struct{})
			m.sources[path] = &source{path: path, logType: s.LogType, stopCh: stopCh}
			go Tail(path, s.LogType, m.buf, stopCh)
		}
	}
}

// StopAll stops all running tailers.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for path, active := range m.sources {
		slog.Info("stopping tailer", "path", path)
		close(active.stopCh)
	}
	m.sources = make(map[string]*source)
}
```

- [ ] **Step 3: Compile check**

```bash
cd agent && go build ./...
```

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add agent/internal/tailer/
git commit -m "feat: add log tailer with file-seek, rotation retry, and dynamic manager"
```

---

## Task 7: Sender Loop & Main Entry Point

**Files:**
- Create: `agent/cmd/agent/main.go`

- [ ] **Step 1: Write main.go**

```go
// agent/cmd/agent/main.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/enrollment"
	"github.com/siem-platform/agent/internal/heartbeat"
	"github.com/siem-platform/agent/internal/tailer"
)

const configPath = "config.yaml"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	enrollToken := os.Getenv("AGENT_ENROLLMENT_TOKEN")
	if enrollToken == "" {
		enrollToken = "bootstrap-token"
	}

	if cfg.Agent.Token == "" {
		if err := enrollment.Enroll(cfg, configPath, enrollToken); err != nil {
			slog.Error("enrollment failed", "err", err)
			os.Exit(1)
		}
	}

	buf := buffer.New(cfg.Agent.BufferSize)
	c := client.New(cfg.Server.URL, cfg.Agent.Token)
	mgr := tailer.NewManager(buf)

	// seed initial sources from config
	initialSources := make([]heartbeat.LogSource, len(cfg.Logs))
	for i, l := range cfg.Logs {
		initialSources[i] = heartbeat.LogSource{Path: l.Path, LogType: l.Type, IsEnabled: true}
	}
	mgr.Update(initialSources)

	// fsnotify for bootstrap fields only
	config.Watch(configPath, func(newCfg *config.Config) {
		cfg.Agent.Name = newCfg.Agent.Name
		cfg.Agent.Group = newCfg.Agent.Group
		cfg.Server.URL = newCfg.Server.URL
		c.BaseURL = newCfg.Server.URL
	})

	// heartbeat loop
	go heartbeat.Loop(cfg, buf, c, func(sources []heartbeat.LogSource) {
		mgr.Update(sources)
	})

	// sender loop
	go senderLoop(buf, c, cfg)

	// signal handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	slog.Info("shutting down")
	mgr.StopAll()
	flushBuffer(buf, c, cfg)
}

func senderLoop(buf *buffer.Buffer, c *client.Client, cfg *config.Config) {
	backoff := time.Second
	for {
		entry, ok := buf.Pop()
		if !ok {
			backoff = time.Second
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logType, rawMessage := tailer.Decode(entry)
		payload := map[string]interface{}{
			"agent_id":    cfg.Agent.ID,
			"agent_token": cfg.Agent.Token,
			"log_type":    logType,
			"raw_message": rawMessage,
			"received_at": time.Now().UTC().Format(time.RFC3339Nano),
			"hostname":    mustHostname(),
		}
		resp, err := c.Post("/api/ingest/log", payload)
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			if resp != nil {
				resp.Body.Close()
			}
			buf.Push(entry) // re-queue
			slog.Warn("send failed, backing off", "backoff", backoff)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		resp.Body.Close()
		backoff = time.Second
	}
}

func flushBuffer(buf *buffer.Buffer, c *client.Client, cfg *config.Config) {
	slog.Info("flushing buffer", "len", buf.Len())
	for {
		entry, ok := buf.Pop()
		if !ok {
			break
		}
		logType, rawMessage := tailer.Decode(entry)
		payload := map[string]interface{}{
			"agent_id":    cfg.Agent.ID,
			"agent_token": cfg.Agent.Token,
			"log_type":    logType,
			"raw_message": rawMessage,
			"received_at": time.Now().UTC().Format(time.RFC3339Nano),
			"hostname":    mustHostname(),
		}
		c.Post("/api/ingest/log", payload)
	}
}

func mustHostname() string {
	h, _ := os.Hostname()
	return h
}
```

- [ ] **Step 2: Compile and build**

```bash
cd agent && go build -o bin/agent ./cmd/agent/
```

Expected: Binary created at `agent/bin/agent` with no errors.

- [ ] **Step 3: Commit**

```bash
git add agent/cmd/
git commit -m "feat: add agent main with sender loop, signal handler, and buffer flush"
```

---

## Task 8: Dockerfile & End-to-End Test

**Files:**
- Create: `agent/Dockerfile`

- [ ] **Step 1: Write Dockerfile**

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /agent ./cmd/agent/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /agent /app/agent
COPY config.yaml /app/config.yaml
CMD ["/app/agent"]
```

- [ ] **Step 2: Build Docker image**

```bash
cd agent && docker build -t siem-agent:local .
```

Expected: Image builds successfully.

- [ ] **Step 3: Run integration test**

```bash
# server-api must be running on localhost:8000
docker run --rm --network host \
  -e AGENT_ENROLLMENT_TOKEN=bootstrap-token \
  -v /var/log:/host/var/log:ro \
  siem-agent:local
```

Expected: Agent logs:
```
{"level":"INFO","msg":"enrollment successful","agent_id":"..."}
{"level":"INFO","msg":"tailing","path":"/host/var/log/auth.log","type":"linux_auth"}
```

- [ ] **Step 4: Commit**

```bash
git add agent/Dockerfile
git commit -m "feat: add agent Dockerfile with multi-stage build"
```

---

## Task 9: Run All Agent Tests

- [ ] **Step 1: Run all Go tests**

```bash
cd agent && go test ./... -v -count=1
```

Expected: All tests in `tests/agent/` PASS.

- [ ] **Step 2: Run go vet and staticcheck**

```bash
go vet ./...
```

Expected: No issues.

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: complete Go agent - enrollment, tail, buffer, heartbeat, sender"
```
