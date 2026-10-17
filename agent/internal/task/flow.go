// agent/internal/task/flow.go
package task

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/client"
)

// FlowSource is one compiled artifact source: a plugin call. Filtering
// (Sigma detection, field projection) happens server-side.
type FlowSource struct {
	Name   string         `json:"name"`
	Plugin string         `json:"plugin"`
	Args   map[string]any `json:"args"`
}

// FlowRequest is what the server hands out on /api/agent/flows/poll.
type FlowRequest struct {
	ID       string       `json:"id"`
	Artifact string       `json:"artifact"`
	Timeout  int          `json:"timeout"`
	MaxRows  int          `json:"max_rows"`
	Sources  []FlowSource `json:"sources"`
}

type flowLog struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type flowUpdate struct {
	State  string           `json:"state,omitempty"`
	Source string           `json:"source,omitempty"`
	Rows   []map[string]any `json:"rows,omitempty"`
	Logs   []flowLog        `json:"logs,omitempty"`
	Error  string           `json:"error,omitempty"`
}

type pollResponse struct {
	Flows  []FlowRequest `json:"flows"`
	Cancel []string      `json:"cancel"`
}

const (
	flowBatchSize      = 500
	flowPollTimeout    = 35 * time.Second // server holds a poll open for 20s
	flowUpdateTimeout  = 30 * time.Second
	flowMaxParallel    = 2
	flowDefaultTimeout = 600
	flowDefaultMaxRows = 10000
	// a plugin stuck in a blocking syscall can't see ctx; after this long it
	// is abandoned so the flow still reports and frees its slot
	pluginStopGrace = 5 * time.Second
)

var (
	errRowLimit = errors.New("row limit reached")
	errFlowGone = errors.New("flow was cancelled or removed on the server")
)

// FlowRunner long-polls the server for live-response flows and runs them.
type FlowRunner struct {
	client  *client.Client
	Plugins map[string]Plugin

	sem     chan struct{}
	mu      sync.Mutex
	running map[string]context.CancelFunc
	parent  context.Context
}

func NewFlowRunner(c *client.Client) *FlowRunner {
	return &FlowRunner{
		client:  c,
		Plugins: Plugins,
		sem:     make(chan struct{}, flowMaxParallel),
		running: map[string]context.CancelFunc{},
		parent:  context.Background(),
	}
}

// Run polls until ctx is done; flows started from it are cancelled with it.
func (r *FlowRunner) Run(ctx context.Context) {
	r.mu.Lock()
	r.parent = ctx
	r.mu.Unlock()
	backoff := time.Second
	for ctx.Err() == nil {
		resp, err := r.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("flow poll failed", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, id := range resp.Cancel {
			r.Cancel(id)
		}
		for _, f := range resp.Flows {
			r.Start(f)
		}
	}
}

func (r *FlowRunner) poll(ctx context.Context) (pollResponse, error) {
	var out pollResponse
	pctx, cancel := context.WithTimeout(ctx, flowPollTimeout)
	defer cancel()
	resp, err := r.client.PostContext(pctx, "/api/agent/flows/poll", struct{}{})
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("poll status %d", resp.StatusCode)
	}
	return out, json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out)
}

// Start runs a flow in the background; a flow already running is ignored.
func (r *FlowRunner) Start(req FlowRequest) {
	r.mu.Lock()
	if _, ok := r.running[req.ID]; ok || req.ID == "" {
		r.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(r.parent)
	r.running[req.ID] = cancel
	r.mu.Unlock()
	go r.run(ctx, cancel, req)
}

// Cancel stops a running flow; unknown ids are ignored.
func (r *FlowRunner) Cancel(id string) {
	r.mu.Lock()
	cancel, ok := r.running[id]
	r.mu.Unlock()
	if ok {
		slog.Info("flow cancel requested", "id", id)
		cancel()
	}
}

// Running reports how many flows are in flight (for tests and diagnostics).
func (r *FlowRunner) Running() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running)
}

type flowExec struct {
	client  *client.Client
	id      string
	cancel  context.CancelFunc
	mu      sync.Mutex // pending is shared with the plugin goroutine's emit
	pending []flowLog
}

func (f *flowExec) log(level, msg string) {
	f.mu.Lock()
	f.pending = append(f.pending, flowLog{Level: level, Message: msg})
	f.mu.Unlock()
}

// send posts an update (with any queued logs) using its own deadline, so the
// final status still gets out after the flow's context is cancelled or timed out.
func (f *flowExec) send(u flowUpdate) error {
	f.mu.Lock()
	u.Logs, f.pending = f.pending, nil
	f.mu.Unlock()
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), flowUpdateTimeout)
		resp, err := f.client.PostContext(ctx, "/api/agent/flows/"+f.id+"/update", u)
		if err != nil {
			cancel()
			lastErr = err
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		var out struct {
			Cancel bool `json:"cancel"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			f.cancel()
			return errFlowGone
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("update status %d", resp.StatusCode)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		case resp.StatusCode >= 400:
			return fmt.Errorf("server rejected update (%d): %s", resp.StatusCode, body)
		}
		if json.Unmarshal(body, &out) == nil && out.Cancel {
			f.cancel()
			return errFlowGone
		}
		return nil
	}
	return fmt.Errorf("update failed after retries: %w", lastErr)
}

func (r *FlowRunner) run(ctx context.Context, cancel context.CancelFunc, req FlowRequest) {
	defer func() {
		cancel()
		r.mu.Lock()
		delete(r.running, req.ID)
		r.mu.Unlock()
	}()
	f := &flowExec{client: r.client, id: req.ID, cancel: cancel}

	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		f.log("warn", "Cancelled before it started")
		_ = f.send(flowUpdate{State: "cancelled"})
		return
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = flowDefaultTimeout
	}
	maxRows := req.MaxRows
	if maxRows <= 0 {
		maxRows = flowDefaultMaxRows
	}
	ctx, stop := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer stop()

	slog.Info("flow started", "id", req.ID, "artifact", req.Artifact)
	f.log("info", fmt.Sprintf("Agent started %s: %d source(s), timeout %ds, max %d rows",
		req.Artifact, len(req.Sources), timeout, maxRows))
	if err := f.send(flowUpdate{State: "running"}); errors.Is(err, errFlowGone) {
		return
	}

	state, errMsg, total := "finished", "", 0
sources:
	for _, src := range req.Sources {
		plugin, ok := r.Plugins[src.Plugin]
		if !ok {
			f.log("error", fmt.Sprintf("%s: this agent has no plugin %q (agent update needed)", src.Name, src.Plugin))
			state, errMsg = "error", "unknown plugin "+src.Plugin
			continue
		}
		// emit runs on the plugin goroutine; once the source is closed (done or
		// abandoned) it refuses rows, so a late plugin can't touch the batch.
		var (
			bmu    sync.Mutex
			batch  []map[string]any
			closed bool
			n      int
		)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			err := f.send(flowUpdate{Source: src.Name, Rows: batch})
			batch = nil
			return err
		}
		emit := func(row map[string]any) error {
			bmu.Lock()
			defer bmu.Unlock()
			if closed {
				return context.Canceled
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if total >= maxRows {
				return errRowLimit
			}
			batch = append(batch, row)
			n++
			total++
			if len(batch) >= flowBatchSize {
				return flush()
			}
			return nil
		}

		began := time.Now()
		done := make(chan error, 1)
		go func(args map[string]any) { done <- plugin(ctx, args, emit) }(src.Args)
		var err error
		select {
		case err = <-done:
		case <-ctx.Done():
			select {
			case err = <-done:
			case <-time.After(pluginStopGrace):
				err = ctx.Err()
				f.log("warn", fmt.Sprintf("%s: plugin %s did not stop within %s and was abandoned",
					src.Name, src.Plugin, pluginStopGrace))
			}
		}
		bmu.Lock()
		closed = true
		ferr := flush()
		count := n
		bmu.Unlock()
		if err == nil || errors.Is(ferr, errFlowGone) {
			err = ferr
		}
		f.log("info", fmt.Sprintf("%s: %d row(s) from %s in %s", src.Name, count, src.Plugin,
			time.Since(began).Round(time.Millisecond)))

		switch {
		case err == nil:
		case errors.Is(err, errFlowGone):
			slog.Info("flow stopped by server", "id", req.ID)
			return
		case errors.Is(err, errRowLimit):
			f.log("warn", fmt.Sprintf("Row limit %d reached; remaining sources skipped", maxRows))
			break sources
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			state, errMsg = "error", fmt.Sprintf("timed out after %ds", timeout)
			f.log("error", errMsg)
			break sources
		case ctx.Err() != nil:
			state = "cancelled"
			f.log("warn", "Cancelled")
			break sources
		default:
			f.log("error", fmt.Sprintf("%s: %v", src.Name, err))
			state, errMsg = "error", fmt.Sprintf("%s: %v", src.Name, err)
		}
	}
	if err := f.send(flowUpdate{State: state, Error: errMsg}); err != nil && !errors.Is(err, errFlowGone) {
		slog.Error("flow final update failed", "id", req.ID, "err", err)
	}
	slog.Info("flow done", "id", req.ID, "state", state, "rows", total)
}
