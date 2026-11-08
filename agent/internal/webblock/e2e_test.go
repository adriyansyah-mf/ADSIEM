package webblock

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const e2eDomain = "adsiem-e2e-blocked.example"

// TestWebBlockE2E drives the real hosts file, trust store and block page
// server on the machine it runs on: Apply a list, resolve and fetch the blocked
// domain over HTTP and HTTPS, deactivate and check everything is gone again.
// It changes the machine, so it runs only in CI (WEBBLOCK_E2E=1, root/admin).
func TestWebBlockE2E(t *testing.T) {
	if os.Getenv("WEBBLOCK_E2E") != "1" {
		t.Skip("set WEBBLOCK_E2E=1 to run the web protection end-to-end test")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skipf("web protection end-to-end is not supported on %s", runtime.GOOS)
	}
	e2eSkipUnlessPrivileged(t)

	stateDir := t.TempDir()
	hostsPath := defaultHostsPath()
	orig, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	// Whatever the test did, leave the runner as it was found.
	t.Cleanup(func() {
		_ = Cleanup(stateDir)
		if cur, err := os.ReadFile(hostsPath); err != nil || !bytes.Equal(cur, orig) {
			// In place: the hosts file may be a bind mount or locked.
			if err := os.WriteFile(hostsPath, orig, 0o644); err != nil {
				t.Errorf("restore hosts file: %v", err)
			}
		}
	})

	var mu sync.Mutex
	var pushed []string
	hostname, _ := os.Hostname()
	newController := func() *Controller {
		return &Controller{
			Hosts:     NewHostsFile(),
			Authority: &TrustStore{Dir: stateDir},
			Server: &Server{Hostname: hostname, Push: func(logType, line string) {
				mu.Lock()
				defer mu.Unlock()
				pushed = append(pushed, line)
			}},
			Hostname: hostname,
			StateDir: stateDir,
		}
	}
	c := newController()

	active := &List{
		Version: "e2e:1", Group: "e2e", Seq: 1, Rules: 1,
		Policy:  Policy{Enabled: true, PageHTML: "<p>{{domain}} is blocked</p>", MaxEntries: 100},
		Entries: map[string]Entry{e2eDomain: {Source: "manual", Reason: "e2e"}},
	}
	c.Apply(active)
	h := c.Health()
	t.Logf("health after apply: %+v", h)
	if h.LastError != "" || !h.CAInstalled {
		t.Fatalf("health after apply: %+v", h)
	}
	assertPageServer(t, h.PageServer)
	caPEM, err := os.ReadFile(filepath.Join(stateDir, CADirName, CACertFile))
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}

	waitResolve(t, true, 5*time.Second)

	// HTTP on port 80.
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	status, body := e2eGet(t, httpClient, "http://"+e2eDomain+"/x")
	if status != 403 || !strings.Contains(body, e2eDomain) {
		t.Fatalf("http: status %d body %q", status, body)
	}

	// HTTPS on 443: the system trust must now include the CA.
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: e2eTLSConfig(t)}
	defer tr.CloseIdleConnections()
	status, body = e2eGet(t, &http.Client{Timeout: 10 * time.Second, Transport: tr}, "https://"+e2eDomain+"/x")
	if status != 403 || !strings.Contains(body, e2eDomain) {
		t.Fatalf("https: status %d body %q", status, body)
	}

	// The server answers first and emits the event afterwards (process lookup,
	// then Push), so poll for it.
	sawEvent := false
	for deadline := time.Now().Add(3 * time.Second); !sawEvent && time.Now().Before(deadline); {
		mu.Lock()
		for _, l := range pushed {
			if strings.HasPrefix(l, "event=web_block") {
				sawEvent = true
			}
		}
		mu.Unlock()
		if !sawEvent {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !sawEvent {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("no web_block event pushed within 3s: %q", pushed)
	}

	// Deactivate.
	c.Apply(Empty())
	if h := c.Health(); h.LastError != "" {
		t.Fatalf("health after deactivate: %+v", h)
	}
	// Go caches the hosts file for 5 s, so allow well over that.
	waitResolve(t, false, 10*time.Second)
	e2eAssertState(t, stateDir, hostsPath, orig, caPEM, "deactivation")

	// Cleanup alone (what package removal runs) undoes a fresh Apply.
	c2 := newController()
	c2.Apply(active)
	if h := c2.Health(); h.LastError != "" || !h.CAInstalled {
		t.Fatalf("health after second apply: %+v", h)
	}
	c2.Server.Stop()
	if err := Cleanup(stateDir); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	e2eAssertState(t, stateDir, hostsPath, orig, caPEM, "Cleanup")
}

func e2eAssertState(t *testing.T, stateDir, hostsPath string, orig, caPEM []byte, after string) {
	t.Helper()
	e2eAssertTrustGone(t, caPEM)
	if _, err := os.Stat(filepath.Join(stateDir, CADirName)); !os.IsNotExist(err) {
		t.Fatalf("after %s: CA directory still present: %v", after, err)
	}
	cur, err := os.ReadFile(hostsPath)
	if err != nil || !bytes.Equal(cur, orig) {
		t.Fatalf("after %s: hosts file differs from the original (err %v)", after, err)
	}
}

// waitResolve polls the system resolution until the domain does (want) or does
// not (!want) resolve to the block page address; the OS may cache for a moment.
func waitResolve(t *testing.T, want bool, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		addrs, err := net.DefaultResolver.LookupHost(context.Background(), e2eDomain)
		got := false
		for _, a := range addrs {
			if a == "127.84.0.1" {
				got = true
			}
		}
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lookup %s: want blocked=%v, got %v (err %v)", e2eDomain, want, addrs, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func e2eGet(t *testing.T, cl *http.Client, url string) (int, string) {
	t.Helper()
	var lastErr error
	for i := 0; i < 10; i++ {
		resp, err := cl.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	t.Fatalf("GET %s: %v", url, lastErr)
	return 0, ""
}

// assertPageServer fails with the bind status unless the IPv4 listeners are
// up; only [::1] failures are tolerated (a runner may have no IPv6 loopback).
func assertPageServer(t *testing.T, status string) {
	t.Helper()
	if status == "ok" {
		return
	}
	rest, found := strings.CutPrefix(status, "page_unavailable: ")
	if found {
		bad := false
		for _, a := range strings.Split(rest, ",") {
			if !strings.Contains(a, "[::1]") {
				bad = true
			}
		}
		if !bad {
			t.Logf("page server without IPv6: %s", status)
			return
		}
	}
	t.Fatalf("block page server could not bind its IPv4 addresses (is another service on port 80/443?): %q", status)
}
