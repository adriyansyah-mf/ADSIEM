package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPost_SelfSignedCert_FailsWithoutSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "", false)
	_, err := c.Post("/api/ingest/log", map[string]string{"x": "y"})
	if err == nil {
		t.Fatal("expected a TLS verification error against a self-signed cert, got none")
	}
}

func TestPost_SelfSignedCert_SucceedsWithSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "", true)
	resp, err := c.Post("/api/ingest/log", map[string]string{"x": "y"})
	if err != nil {
		t.Fatalf("expected success with InsecureSkipVerify, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPost_SendsAgentTokenHeader(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Agent-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "secret-token", false)
	resp, err := c.Post("/api/ingest/log", map[string]string{"x": "y"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if gotToken != "secret-token" {
		t.Fatalf("expected X-Agent-Token header %q, got %q", "secret-token", gotToken)
	}
}

// TestPost_RefusesRedirect proves the fix for the real bug this test suite
// was added for: Go's default http.Client silently downgrades a POST to a
// GET (dropping the request body) when following a 301/302/303 redirect --
// exactly what happens if server.url is configured for plain HTTP against a
// server that now redirects to HTTPS. The client must fail loudly instead
// of silently losing the payload.
func TestPost_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("redirect target must never be reached: the body would already be lost by the time a real server saw this request")
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/ingest/log", http.StatusMovedPermanently)
	}))
	defer redirector.Close()

	c := New(redirector.URL, "", false)
	_, err := c.Post("/api/ingest/log", map[string]string{"x": "y"})
	if err == nil {
		t.Fatal("expected an error refusing the redirect, got none")
	}
}
