package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/policy"
)

func withServiceManager(t *testing.T, under bool) {
	t.Helper()
	prev := inServiceManager
	inServiceManager = func() bool { return under }
	restartRequested.Store(false)
	t.Cleanup(func() {
		inServiceManager = prev
		restartRequested.Store(false)
	})
}

func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestRestartAfterNotUnderManagerOnlyLogs(t *testing.T) {
	withServiceManager(t, false)
	stop := make(chan struct{})
	restartAfter(stop, 0)
	restartAfter(stop, 0)
	if closed(stop) {
		t.Fatal("stop closed outside a service manager")
	}
	if restartRequested.Load() {
		t.Fatal("restartRequested set outside a service manager")
	}
}

func TestRestartAfterUnderManagerCloses(t *testing.T) {
	withServiceManager(t, true)
	stop := make(chan struct{})
	restartAfter(stop, time.Millisecond)
	if !closed(stop) {
		t.Fatal("stop not closed under a service manager")
	}
	if !restartRequested.Load() {
		t.Fatal("restartRequested not set")
	}
	// A second restart must not close the channel again (that would panic).
	restartAfter(stop, 0)
}

func TestRestartAfterConcurrentClosesOnce(t *testing.T) {
	withServiceManager(t, true)
	stop := make(chan struct{})
	done := make(chan struct{})
	for range 5 {
		go func() { restartAfter(stop, time.Millisecond); done <- struct{}{} }()
	}
	for range 5 {
		<-done
	}
	if !closed(stop) {
		t.Fatal("stop not closed")
	}
}

func TestProbeServerSendsTokenAndChecksStatus(t *testing.T) {
	status := http.StatusOK
	var gotPath, gotToken, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotToken, gotMethod = r.URL.Path, r.Header.Get("X-Agent-Token"), r.Method
		w.WriteHeader(status)
	}))
	defer srv.Close()

	probe := probeServer(client.New("https://unused.example", "tok"))
	if err := probe(srv.URL); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if gotPath != policy.Path || gotToken != "tok" || gotMethod != http.MethodPost {
		t.Fatalf("request = %s %s token %q", gotMethod, gotPath, gotToken)
	}
	status = http.StatusUnauthorized
	if err := probe(srv.URL); err == nil {
		t.Fatal("probe accepted a 401")
	}
}
