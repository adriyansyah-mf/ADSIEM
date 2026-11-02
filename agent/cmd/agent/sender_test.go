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

// With a server that takes batches, the backlog goes in a few requests and a
// detection queued last is in the first one.
func TestSenderBatchesWithDetectionsFirst(t *testing.T) {
	old := logBatchMax
	logBatchMax = func() int { return 3 }
	defer func() { logBatchMax = old }()
	type entry struct {
		LogType    string `json:"log_type"`
		RawMessage string `json:"raw_message"`
	}
	batches := make(chan []entry, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Entries []entry `json:"entries"`
		}
		if r.URL.Path != "/api/ingest/logs" || json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Errorf("request %s", r.URL.Path)
		}
		batches <- body.Entries
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	buf := buffer.New(100)
	buf.SetUrgent(isUrgentEntry)
	for _, m := range []string{"one", "two", "three", "four"} {
		buf.Push("windows_etw_image\x00" + m)
	}
	buf.Push("known_malware\x00event=known_malware action=detected")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		senderLoop(ctx, buf, client.New(server.URL, "token"), &config.Config{}, nil, nil)
	}()
	var got [][]entry
	for len(got) < 2 {
		select {
		case b := <-batches:
			got = append(got, b)
		case <-time.After(3 * time.Second):
			t.Fatalf("batches: %v", got)
		}
	}
	cancel()
	<-done
	if len(got[0]) != 3 || got[0][0].LogType != "known_malware" || got[0][1].RawMessage != "one" || len(got[1]) != 2 {
		t.Fatalf("batches: %+v", got)
	}
}

// A refused token is retried with a backoff and nothing is dropped (it used
// to drop every entry and send the next at once: thousands of requests a second).
func TestSenderBacksOffOnARefusedToken(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	buf := buffer.New(10)
	buf.Push("syslog\x00one")
	buf.Push("syslog\x00two")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	senderLoop(ctx, buf, client.New(server.URL, "bad"), &config.Config{}, nil, nil)
	if n := requests.Load(); n < 1 || n > 2 {
		t.Fatalf("requests=%d, want a backoff between tries", n)
	}
	if buf.Len() != 2 {
		t.Fatalf("entries dropped: %d left", buf.Len())
	}
}
