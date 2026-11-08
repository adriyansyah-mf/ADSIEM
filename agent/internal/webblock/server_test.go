package webblock

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPage = "<p>{{domain}} {{ reason }} {{source}} {{time}} {{hostname}} {{contact}}</p>{{other}}"

func testLookup(host string) (Entry, bool) {
	if host == "evil.example" {
		return Entry{Source: "urlhaus", Reason: `bad "stuff" <b>`}, true
	}
	return Entry{}, false
}

type captured struct {
	mu    sync.Mutex
	lines []string
}

func (c *captured) push(logType, line string) {
	if logType != LogType {
		return
	}
	c.mu.Lock()
	c.lines = append(c.lines, line)
	c.mu.Unlock()
}

func (c *captured) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// wait returns the events once at least n arrived (the handler emits after
// the response is written).
func (c *captured) wait(n int) []string {
	for i := 0; i < 200; i++ {
		if l := c.get(); len(l) >= n {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c.get()
}

func newTestHandlerServer() (*Server, *captured) {
	c := &captured{}
	s := &Server{Push: c.push, Hostname: "WS-1", Now: func() time.Time { return time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC) }}
	s.set(testPage, "sec <team>", testLookup)
	return s, c
}

func serve(t *testing.T, s *Server, method, host string) (*http.Response, string) {
	t.Helper()
	srv := newHTTPTestServer(t, s)
	req, _ := http.NewRequest(method, srv+"/a/b?x=1", strings.NewReader("ignored body"))
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func newHTTPTestServer(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := s.newHTTPServer()
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	return "http://" + ln.Addr().String()
}

func TestHandlerListedHost(t *testing.T) {
	s, c := newTestHandlerServer()
	resp, body := serve(t, s, "GET", "EVIL.example:8080")
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'",
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
		"Content-Type":            "text/html; charset=utf-8",
	} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
	want := Document(testPage, map[string]string{"domain": "evil.example", "reason": `bad "stuff" <b>`, "source": "urlhaus",
		"time": "2026-11-08 10:05 UTC", "hostname": "WS-1", "contact": "sec <team>"})
	if body != want {
		t.Fatalf("body\n%s\nwant\n%s", body, want)
	}
	if !strings.Contains(body, "bad &quot;stuff&quot; &lt;b&gt;") || !strings.Contains(body, "{{other}}") {
		t.Fatal("escaping")
	}
	lines := c.wait(1)
	if len(lines) != 1 || !strings.Contains(lines[0], `domain="evil.example" scheme=http path="/a/b" source="urlhaus"`) {
		t.Fatalf("events %v", lines)
	}
}

func TestHandlerUnknownHostFallback(t *testing.T) {
	s, c := newTestHandlerServer()
	r := httptest.NewRequest("POST", "/", nil)
	r.Host = "<script>.test:81"
	w := httptest.NewRecorder()
	s.handle(w, r)
	body := w.Body.String()
	if w.Code != 403 || !strings.Contains(body, "Blocked by your organisation policy") ||
		!strings.Contains(body, "&lt;script&gt;.test") || strings.Contains(body, "<script>") {
		t.Fatalf("body %s", body)
	}
	if l := c.wait(1); len(l) != 1 || !strings.Contains(l[0], `reason="Blocked by your organisation"`) {
		t.Fatalf("events %v", l)
	}
}

func TestHandlerHeadHasNoBody(t *testing.T) {
	s, _ := newTestHandlerServer()
	resp, body := serve(t, s, "HEAD", "evil.example")
	if resp.StatusCode != 403 || body != "" || resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestHandlerRateLimitsEvents(t *testing.T) {
	s, c := newTestHandlerServer()
	for i := 0; i < 3; i++ {
		serve(t, s, "GET", "evil.example")
	}
	c.wait(1)
	time.Sleep(50 * time.Millisecond)
	if n := len(c.get()); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"Evil.Example:80": "evil.example", "evil.example.": "evil.example", "[::1]:443": "::1", "[::1]": "::1", "x": "x", "": "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func startTestServer(t *testing.T, ca *CA, addrs Addrs) (*Server, *captured, string) {
	t.Helper()
	c := &captured{}
	s := &Server{Push: c.push, Hostname: "WS-1", Addrs: addrs}
	_, status := s.Start(testPage, "sec", testLookup, ca)
	t.Cleanup(s.Stop)
	return s, c, status
}

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, _, err := LoadOrCreateCA(t.TempDir(), "WS-1")
	if err != nil {
		t.Fatal(err)
	}
	ca.SetAllowed(func(h string) bool { _, ok := testLookup(h); return ok })
	return ca
}

func TestServerHTTPAndHTTPS(t *testing.T) {
	ca := testCA(t)
	s, c, status := startTestServer(t, ca, Addrs{HTTP4: "127.0.0.1:0", HTTPS4: "127.0.0.1:0"})
	if status != "ok" {
		t.Fatal(status)
	}
	b := s.Bound()

	resp, err := http.Get("http://" + b.HTTP4)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("http %d", resp.StatusCode)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM())
	conf := &tls.Config{RootCAs: pool, ServerName: "evil.example"}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: conf,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", b.HTTPS4)
		},
	}}
	hresp, err := client.Get("https://evil.example/p")
	if err != nil {
		t.Fatal(err)
	}
	hbody, _ := io.ReadAll(hresp.Body)
	hresp.Body.Close()
	if hresp.StatusCode != 403 || !strings.Contains(string(hbody), "evil.example") {
		t.Fatalf("https %d %s", hresp.StatusCode, hbody)
	}
	if l := c.wait(1); len(l) == 0 || !strings.Contains(l[len(l)-1], "scheme=https") {
		t.Fatalf("events %v", l)
	}

	bad := &tls.Config{RootCAs: pool, ServerName: "unlisted.example"}
	if c2, err := tls.Dial("tcp", b.HTTPS4, bad); err == nil {
		c2.Close()
		t.Fatal("handshake for an unlisted SNI succeeded")
	}
}

func TestStartOccupiedPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	s, _, status := startTestServer(t, nil, Addrs{HTTP4: busy.Addr().String(), HTTPS4: "127.0.0.1:0"})
	if !strings.HasPrefix(status, "page_unavailable: ") || !strings.Contains(status, busy.Addr().String()) {
		t.Fatalf("status %q", status)
	}
	if s.Bound().HTTP4 != "" {
		t.Fatal("occupied listener reported as bound")
	}
}

func TestStartTwiceSwapsPage(t *testing.T) {
	s, _, _ := startTestServer(t, nil, Addrs{HTTP4: "127.0.0.1:0"})
	addr := s.Bound().HTTP4
	s.Start("<i>second {{domain}}</i>", "c", testLookup, nil)
	if s.Bound().HTTP4 != addr {
		t.Fatal("rebound")
	}
	resp, err := http.Get("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "<i>second ") {
		t.Fatalf("%s", b)
	}
	s.Stop()
	s.Stop()
	if _, err := http.Get("http://" + addr); err == nil {
		t.Fatal("still serving after Stop")
	}
}
