package dnssink

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/appcontrol"
)

// TestSinkholeEndToEnd routes a domain through the host's real resolver
// (systemd-resolved on Linux, NRPT and the DNS Client on Windows): root or
// Administrator, DNSSINK_E2E=1 (CI only; it changes the host's DNS routing).
func TestSinkholeEndToEnd(t *testing.T) {
	if os.Getenv("DNSSINK_E2E") != "1" {
		t.Skip("set DNSSINK_E2E=1 (root/Administrator, changes DNS routing)")
	}
	const domain = "adsiem-sinkhole-e2e.test"
	lookup := func(name string) []string {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(ctx, name)
		if err != nil {
			return []string{"error: " + err.Error()}
		}
		return addrs
	}
	sinked := func(addrs []string) bool {
		for _, a := range addrs {
			if a == "127.84.0.1" {
				return true
			}
		}
		return false
	}
	waitFor := func(name string, want bool) []string {
		var got []string
		for i := 0; i < 20; i++ {
			if got = lookup(name); sinked(got) == want {
				return got
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s: sinked=%v wanted %v, got %v", name, !want, want, got)
		return nil
	}

	var mu sync.Mutex
	var lines []string
	c := &Controller{Router: NewRouter(PSRunner(appcontrol.PowerShell())),
		Push: func(_, l string) { mu.Lock(); lines = append(lines, l); mu.Unlock(); t.Log(l) }}
	defer c.Apply(false, nil)
	c.Apply(true, []string{domain})
	mu.Lock()
	if len(lines) == 0 || !strings.Contains(lines[0], "routed=true") {
		mu.Unlock()
		t.Fatalf("not routed on %s: %v", runtime.GOOS, lines)
	}
	mu.Unlock()

	waitFor("deep.sub."+domain, true)
	waitFor(domain, true)
	if got := lookup("example.com"); sinked(got) || strings.HasPrefix(got[0], "error") {
		t.Fatalf("another name must resolve as before: %v", got)
	}
	if c.srv.Answered() == 0 {
		t.Fatal("the resolver answered nothing")
	}

	c.Apply(false, nil)
	waitFor("deep.sub."+domain, false)
	if got := lookup("example.com"); strings.HasPrefix(got[0], "error") {
		t.Fatalf("off broke DNS: %v", got)
	}
}
