package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
)

// The legacy sender's shutdown (no durable journal): it stops when asked,
// the in-flight entry is not lost, and the last flush is bounded and keeps
// what it could not send in the spill.

func TestSenderStopsAndRequeuesTheInFlightEntry(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if once.CompareAndSwap(false, true) {
			close(started)
		}
		<-release
	}))
	defer server.Close()
	defer close(release)
	buf := buffer.New(5)
	buf.Push("syslog\x00hello")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		senderLoop(ctx, buf, client.New(server.URL, "token"), &config.Config{}, nil, nil)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not stop on cancel")
	}
	if entry, ok := buf.Pop(); !ok || entry != "syslog\x00hello" {
		t.Fatalf("in-flight entry lost: %q", entry)
	}
}

func TestFlushRetriesServerErrorsAndKeepsTheContract(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/api/ingest/log" || payload["raw_message"] != "hello" || payload["log_type"] != "syslog" || payload["agent_id"] != "agent" {
			t.Errorf("request %s %v", r.URL.Path, payload)
		}
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	buf := buffer.New(5)
	buf.Push("syslog\x00hello")
	cfg := &config.Config{}
	cfg.Agent.ID, cfg.Agent.Token = "agent", "token"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	flushBuffer(ctx, buf, client.New(server.URL, "token"), cfg, nil)
	if requests.Load() != 2 || buf.Len() != 0 {
		t.Fatalf("requests=%d remaining=%d", requests.Load(), buf.Len())
	}
}

func TestFlushDropsARejectedEntryAndGoesOn(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	buf := buffer.New(5)
	buf.Push("syslog\x00bad")
	buf.Push("syslog\x00good")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	flushBuffer(ctx, buf, client.New(server.URL, ""), &config.Config{}, nil)
	if requests.Load() != 2 || buf.Len() != 0 {
		t.Fatalf("requests=%d remaining=%d", requests.Load(), buf.Len())
	}
}

// The server is down at shutdown: the flush stops at its deadline and the
// entries go to the spill, where the next start's replay finds them.
func TestFlushDeadlineKeepsUnsentEntriesInTheSpill(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	spill, err := buffer.OpenSpill(filepath.Join(t.TempDir(), "spill.log"))
	if err != nil {
		t.Fatal(err)
	}
	buf := buffer.New(5)
	buf.Push("syslog\x00one")
	buf.Push("syslog\x00two")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	flushBuffer(ctx, buf, client.New(server.URL, ""), &config.Config{}, spill)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("flush took %v past its 300 ms deadline", took)
	}
	if buf.Len() != 0 {
		t.Fatalf("%d entries left in memory", buf.Len())
	}
	kept := spill.Drain()
	if len(kept) != 2 || kept[0] != "syslog\x00one" || kept[1] != "syslog\x00two" {
		t.Fatalf("spill = %q", kept)
	}
}
