package webblock

import (
	"strings"
	"testing"
	"time"
)

func TestEventLine(t *testing.T) {
	e := Event{Domain: "evil.example", Scheme: "https", Path: "/a", Source: "urlhaus", Reason: "plain"}
	if got, want := e.Line(), `event=web_block action=blocked domain="evil.example" scheme=https path="/a" source="urlhaus" reason="plain"`; got != want {
		t.Fatalf("%s", got)
	}
	e = Event{Domain: "d", Scheme: "http", Path: "/", Source: "manual", Reason: "say \"hi\"\nback\\slash\r", Process: `a"b`, PID: 42, Count: 3}
	want := `event=web_block action=blocked domain="d" scheme=http path="/" source="manual" reason="say \"hi\"\nback\\slash\r" process="a\"b" pid=42 count=3`
	if got := e.Line(); got != want {
		t.Fatalf("%s\n%s", got, want)
	}
	e.Count = 1
	if strings.Contains(e.Line(), "count=") {
		t.Fatal("count shown for 1")
	}
}

func TestLimiter(t *testing.T) {
	var l Limiter
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if emit, n := l.Allow("a.example", 1, t0); !emit || n != 0 {
		t.Fatal("first")
	}
	for i := 1; i <= 3; i++ {
		if emit, _ := l.Allow("a.example", 1, t0.Add(time.Duration(i)*10*time.Second)); emit {
			t.Fatal("within the minute")
		}
	}
	if emit, _ := l.Allow("a.example", 2, t0.Add(time.Second)); !emit {
		t.Fatal("other pid")
	}
	if emit, _ := l.Allow("b.example", 1, t0.Add(time.Second)); !emit {
		t.Fatal("other domain")
	}
	if emit, n := l.Allow("a.example", 1, t0.Add(61*time.Second)); !emit || n != 3 {
		t.Fatalf("after a minute: %v %d", emit, n)
	}
	if emit, n := l.Allow("a.example", 1, t0.Add(125*time.Second)); !emit || n != 0 {
		t.Fatalf("next: %v %d", emit, n)
	}
}
