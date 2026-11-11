package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func init() { downloadBackoff = func(int) time.Duration { return time.Millisecond } }

// cutServer serves body with Range support (http.ServeContent); the first
// cuts responses are dropped after cutAt bytes, as a lossy link does.
func cutServer(t *testing.T, body []byte, cuts int32, cutAt int) (*httptest.Server, *atomic.Int32, *[]string) {
	var n atomic.Int32
	var ranges []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Token") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ranges = append(ranges, r.Header.Get("Range"))
		if n.Add(1) <= cuts {
			// headers say the whole rest; only part of it is sent
			start := 0
			if rg := r.Header.Get("Range"); rg != "" {
				start = int(rangeStartOf(t, rg))
			}
			hj, _ := w.(http.Hijacker)
			conn, buf, _ := hj.Hijack()
			status := "200 OK"
			extra := ""
			if start > 0 {
				status = "206 Partial Content"
				extra = "Content-Range: bytes " + itoa(start) + "-" + itoa(len(body)-1) + "/" + itoa(len(body)) + "\r\n"
			}
			buf.WriteString("HTTP/1.1 " + status + "\r\nContent-Length: " + itoa(len(body)-start) + "\r\n" + extra + "\r\n")
			end := start + cutAt
			if end > len(body) {
				end = len(body)
			}
			buf.Write(body[start:end])
			buf.Flush()
			conn.Close()
			return
		}
		http.ServeContent(w, r, "p.msi", time.Time{}, bytes.NewReader(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &n, &ranges
}

func itoa(i int) string { return strconv.Itoa(i) }

func rangeStartOf(t *testing.T, rg string) int64 {
	v, ok := rangeStart("bytes " + strings.TrimPrefix(strings.TrimSuffix(rg, "-"), "bytes=") + "-x/y")
	if !ok {
		t.Fatalf("bad range %q", rg)
	}
	return v
}

func payload(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDownloadResumesAfterDrops(t *testing.T) {
	body := payload(t, 3<<20)
	srv, n, ranges := cutServer(t, body, 3, 700_000) // three drops, each after 700 kB
	var got bytes.Buffer
	c := &Client{BaseURL: srv.URL, AgentToken: "tok"}
	if err := c.Download(context.Background(), "/p", WriterErrors(&got)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), body) {
		t.Fatalf("got %d bytes, content differs: %v", got.Len(), !bytes.Equal(got.Bytes(), body))
	}
	want := []string{"", "bytes=700000-", "bytes=1400000-", "bytes=2100000-"}
	if n.Load() != 4 || strings.Join(*ranges, ",") != strings.Join(want, ",") {
		t.Fatalf("requests %d ranges %q", n.Load(), *ranges)
	}
}

func TestDownloadGivesUpAfterAttempts(t *testing.T) {
	body := payload(t, 1<<20)
	srv, n, _ := cutServer(t, body, 100, 10) // every connection drops
	var got bytes.Buffer
	c := &Client{BaseURL: srv.URL, AgentToken: "tok"}
	err := c.Download(context.Background(), "/p", &got)
	if err == nil || int(n.Load()) != DownloadAttempts || !strings.Contains(err.Error(), "after 60 bytes") {
		t.Fatalf("err %v after %d requests", err, n.Load())
	}
}

func TestDownloadServerWithoutRanges(t *testing.T) {
	// first response dropped; the server then ignores Range and sends 200
	body := payload(t, 100_000)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			hj, _ := w.(http.Hijacker)
			conn, buf, _ := hj.Hijack()
			buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
			buf.Write(body[:500])
			buf.Flush()
			conn.Close()
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	var got bytes.Buffer
	err := (&Client{BaseURL: srv.URL}).Download(context.Background(), "/p", &got)
	if err == nil || !strings.Contains(err.Error(), "cannot resume") || got.Len() != 500 {
		t.Fatalf("err %v, %d bytes", err, got.Len())
	}
}

func TestDownloadWriterErrorIsNotRetried(t *testing.T) {
	body := payload(t, 200_000)
	srv, n, _ := cutServer(t, body, 0, 0)
	c := &Client{BaseURL: srv.URL, AgentToken: "tok"}
	full := errors.New("package is larger than its signed size")
	err := c.Download(context.Background(), "/p", WriterErrors(failAfter{1000, full}))
	if !errors.Is(err, full) || n.Load() != 1 {
		t.Fatalf("err %v after %d requests", err, n.Load())
	}
}

func TestDownloadHTTPErrors(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	err := (&Client{BaseURL: srv.URL}).Download(context.Background(), "/p", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "404") || n.Load() != 1 {
		t.Fatalf("404: %v after %d", err, n.Load())
	}
}

type failAfter struct {
	n   int
	err error
}

func (f failAfter) Write(p []byte) (int, error) { return 0, f.err }
