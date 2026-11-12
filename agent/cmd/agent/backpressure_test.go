package main

import (
	"context"
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

// A 429 from a backed-up server used to count as "sent": the line was dropped.
// Now the agent declares it can be pushed back, holds the lines, and resends
// them after the server's Retry-After.

func TestSenderHoldsLinesOn429AndResendsAfterRetryAfter(t *testing.T) {
	var requests, withHeader atomic.Int32
	delivered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Ingest-Backpressure") == "1" {
			withHeader.Add(1)
		}
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		close(delivered)
	}))
	defer server.Close()
	spill, err := buffer.OpenSpill(filepath.Join(t.TempDir(), "spill.log"))
	if err != nil {
		t.Fatal(err)
	}
	buf := buffer.New(5)
	buf.Push("syslog\x00hello")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	go senderLoop(ctx, buf, client.New(server.URL, "token"), &config.Config{}, spill, nil)
	select {
	case <-delivered:
	case <-ctx.Done():
		t.Fatalf("line never delivered after a 429 (requests=%d)", requests.Load())
	}
	if waited := time.Since(start); waited < 900*time.Millisecond {
		t.Fatalf("resent after %v, before the 1s Retry-After", waited)
	}
	if requests.Load() != 2 || withHeader.Load() != 2 {
		t.Fatalf("requests=%d with backpressure header=%d", requests.Load(), withHeader.Load())
	}
	if kept := spill.Drain(); len(kept) != 0 {
		t.Fatalf("a busy server is not an outage, nothing should spill: %q", kept)
	}
}

func TestDeliveryResultRetries429(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Retry-After", "7")
	rec.WriteHeader(http.StatusTooManyRequests)
	sent, err := deliveryResult(rec.Result(), "batch")
	busy, ok := err.(*retryAfterError)
	if sent || !ok || busy.delay != 7*time.Second {
		t.Fatalf("sent=%v err=%v", sent, err)
	}
}

func TestIngestRetryAfterIsBounded(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 5 * time.Second, "junk": 5 * time.Second, "0": 5 * time.Second,
		"3": 3 * time.Second, "86400": 5 * time.Minute,
	} {
		if got := ingestRetryAfter(in); got != want {
			t.Errorf("ingestRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}
