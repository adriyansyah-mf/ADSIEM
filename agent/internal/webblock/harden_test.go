package webblock

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestKVEscapesControls(t *testing.T) {
	got := kv("a\tb\x00c\x1bd\x7fe f g\u0085h\"\\é")
	want := "\"a\\tb\\u0000c\\u001bd\\u007fe\\u2028f\\u2029g\\u0085h\\\"\\\\é\""
	if got != want {
		t.Fatalf("%s\n%s", got, want)
	}
	if strings.ContainsAny(got, "\n\r\t\x00\x1b\x7f  \u0085") {
		t.Fatal("raw control left")
	}
}

func TestTruncRunes(t *testing.T) {
	s := strings.Repeat("é", 10) // 2 bytes each
	for n := 0; n < 21; n++ {
		if got := truncRunes(s, n); !utf8.ValidString(got) || len(got) > n {
			t.Fatalf("n=%d got %q", n, got)
		}
	}
}

func TestLimiterGlobalCap(t *testing.T) {
	var l Limiter
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	emitted := 0
	for i := 0; i < 500; i++ {
		if ok, _ := l.Allow(fmt.Sprintf("h%d.example", i), 1, t0.Add(time.Duration(i)*50*time.Millisecond)); ok {
			emitted++
		}
	}
	if emitted != globalMax {
		t.Fatalf("emitted %d, want %d", emitted, globalMax)
	}
	if ok, _ := l.Allow("later.example", 1, t0.Add(2*time.Minute)); !ok {
		t.Fatal("cap did not reset")
	}
}

func TestServerEventFloodCapped(t *testing.T) {
	s, c := newTestHandlerServer()
	s.set(testPage, "c", func(string) (Entry, bool) { return Entry{Source: "manual"}, true })
	for i := 0; i < 500; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = fmt.Sprintf("h%d.example", i)
		s.handle(httptest.NewRecorder(), r)
	}
	s.emits.Wait()
	if n := len(c.get()); n == 0 || n > globalMax {
		t.Fatalf("%d lines", n)
	}
}

func TestProcessLookupThrottledAndFlushed(t *testing.T) {
	s, c := newTestHandlerServer()
	s.set(testPage, "c", func(h string) (Entry, bool) { return Entry{Source: "manual"}, strings.HasPrefix(h, "evil") })
	var calls int32
	s.findProc = func(string) (int, string) {
		atomic.AddInt32(&calls, 1)
		// far above CI scheduling jitter under -race, still inside wait()'s 2 s
		time.Sleep(1500 * time.Millisecond)
		return 7, "slow"
	}
	base := newHTTPTestServer(t, s)

	var wg sync.WaitGroup
	var bodyDelay time.Duration
	var dm sync.Mutex
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			req, _ := http.NewRequest("GET", base+"/", nil)
			req.Host = fmt.Sprintf("evil%d.example", i)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()
			dm.Lock()
			defer dm.Unlock()
			if d := time.Since(start); d > bodyDelay {
				bodyDelay = d // racy max is fine: only checked loosely below
			}
		}(i)
	}
	wg.Wait()
	if bodyDelay > 750*time.Millisecond {
		t.Fatalf("body took %v; the page waited for the process lookup", bodyDelay)
	}
	c.wait(2)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("%d lookups, want 1", n)
	}
}

// A browser reuses its keep-alive connection for the next request (favicon,
// another tab): that request must not wait for the previous one's process
// lookup.
func TestNextRequestOnConnectionSkipsLookupWait(t *testing.T) {
	s, _ := newTestHandlerServer()
	s.set(testPage, "c", func(string) (Entry, bool) { return Entry{Source: "manual"}, true })
	s.findProc = func(string) (int, string) {
		time.Sleep(1500 * time.Millisecond)
		return 7, "slow"
	}
	base := newHTTPTestServer(t, s)
	client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}
	defer client.CloseIdleConnections()
	for i := 0; i < 2; i++ {
		start := time.Now()
		resp, err := client.Get(base + "/")
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if d := time.Since(start); d > 750*time.Millisecond {
			t.Fatalf("request %d took %v on the shared connection", i+1, d)
		}
	}
	s.emits.Wait()
}
