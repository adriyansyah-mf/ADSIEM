package ipblock

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/tailer"
)

// fakeServer answers /api/ingest/ip-blocklist from a queue of pages.
type fakeServer struct {
	pages    []page
	requests []map[string]any
}

func (f *fakeServer) PostContext(_ context.Context, path string, payload any) (*http.Response, error) {
	if path != Path {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	f.requests = append(f.requests, payload.(map[string]any))
	p := f.pages[0]
	f.pages = f.pages[1:]
	body, _ := json.Marshal(p)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func TestSyncPagesRemovalsOffAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_blocklist.json")
	s := Open(path)
	var installed []*List
	s.OnChange = func(l *List) { installed = append(installed, l) }
	srv := &fakeServer{pages: []page{
		{Group: "blue", Mode: "block", Seq: 2, Reset: true, More: true,
			Changes: []change{{CIDR: "45.33.32.156/32", Action: "block", Source: "manual", Reason: "c2"}}},
		{Group: "blue", Mode: "block", Seq: 3, Version: "blue:3:block",
			Changes: []change{{CIDR: "8.8.4.0/24", Action: "block", Source: "soar"}}},
	}}
	if err := s.Sync(context.Background(), srv, "blue:3:block"); err != nil {
		t.Fatal(err)
	}
	cur := s.Current()
	if cur.Version != "blue:3:block" || cur.Mode != "block" || len(cur.Entries) != 2 || len(installed) != 1 {
		t.Fatalf("after first sync: %+v", cur)
	}
	if srv.requests[1]["continuing"] != true || srv.requests[1]["since"] != int64(2) {
		t.Fatalf("second page request: %v", srv.requests[1])
	}

	// a delta from seq 3 removes one entry; a restart loads it from disk
	srv.pages = []page{{Group: "blue", Mode: "detect", Seq: 4, Version: "blue:4:detect",
		Changes: []change{{CIDR: "8.8.4.0/24", Action: "remove"}}}}
	if err := s.Sync(context.Background(), srv, "blue:4:detect"); err != nil {
		t.Fatal(err)
	}
	if srv.requests[2]["since"] != int64(3) {
		t.Fatalf("delta must start at the saved seq: %v", srv.requests[2])
	}
	reopened := Open(path).Current()
	if reopened.Mode != "detect" || len(reopened.Entries) != 1 || reopened.Entries["45.33.32.156/32"].Reason != "c2" {
		t.Fatalf("reloaded list: %+v", reopened)
	}

	// off drops everything
	if err := s.Sync(context.Background(), srv, ""); err != nil {
		t.Fatal(err)
	}
	if s.Current().Mode != "off" || len(s.Current().Entries) != 0 || Open(path).Current().Version != "" {
		t.Fatalf("off must clear the list and the saved file: %+v", s.Current())
	}
}

func TestSyncFromAnotherGroupStartsOver(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "l.json"))
	srv := &fakeServer{pages: []page{{Group: "blue", Mode: "block", Seq: 9, Reset: true, Version: "blue:9:block",
		Changes: []change{{CIDR: "45.33.32.156/32", Action: "block"}}}}}
	_ = s.Sync(context.Background(), srv, "blue:9:block")
	srv.pages = []page{{Group: "red", Mode: "block", Seq: 2, Reset: true, Version: "red:2:block",
		Changes: []change{{CIDR: "8.8.8.8/32", Action: "block"}}}}
	if err := s.Sync(context.Background(), srv, "red:2:block"); err != nil {
		t.Fatal(err)
	}
	if srv.requests[1]["since"] != int64(0) {
		t.Fatalf("a new group must sync from zero: %v", srv.requests[1])
	}
	if _, old := s.Current().Entries["45.33.32.156/32"]; old || len(s.Current().Entries) != 1 {
		t.Fatalf("entries: %v", s.Current().Entries)
	}
}

func TestRoutine(t *testing.T) {
	for _, c := range []struct {
		cur, want string
		ok        bool
	}{
		{"blue:3:block", "blue:4:block", true},
		{"blue:3:block", "blue:4:block+", true},
		{"blue:3:block", "blue:4:detect", false}, // a mode change applies now
		{"blue:3:block", "red:4:block", false},
		{"", "blue:4:block", false},
		{"blue:3:block", "", false},
	} {
		if got := routine(c.cur, c.want); got != c.ok {
			t.Fatalf("routine(%q, %q) = %v", c.cur, c.want, got)
		}
	}
}

func list(mode string, cidrs ...string) *List {
	l := Empty()
	l.Mode = mode
	for _, c := range cidrs {
		l.Entries[c] = Entry{Source: "manual", Reason: "known C2"}
	}
	return l
}

type sink struct{ lines []map[string]any }

func (s *sink) push(logType, line string) {
	if logType != LogType {
		panic(logType)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(line), &m)
	s.lines = append(s.lines, m)
}

func TestWatcherMatchesLinuxWindowsAndSnapshotLines(t *testing.T) {
	out := &sink{}
	enforced := true
	w := NewWatcher(out.push, func() bool { return enforced })
	w.Update(list("block", "45.33.32.156/32", "8.8.4.0/24", "2606:4700:4700::/48"))

	lines := []struct{ logType, line string }{
		{"linux_network_connect", "ts=x pid=10 tgid=10 uid=0 gid=0 comm=curl action=network_connect proto=tcp direction=outbound src=10.0.0.5 dport=443 dst=45.33.32.156 lport=0 host= private_dst=false"},
		{"linux_network_accept", "ts=x pid=11 tgid=11 uid=0 gid=0 comm=sshd action=network_accept proto=tcp direction=inbound src=8.8.4.77 dport=0 dst=10.0.0.5 lport=22 host= private_dst=true"},
		{"windows_etw_network", `EventID=3 Channel="ETW" ProcessId="4242" Image="C:\Users\a\evil.exe" Initiated="true" SourceIp="10.0.0.5" DestinationIp="2606:4700:4700::1111" DestinationPort="443"`},
		{"linux_network_snapshot", `tcp ESTAB 0 0 10.0.0.5:51000 45.33.32.156:4444 users:(("nc",pid=777,fd=3))`},
		{"linux_network_connect", "ts=x pid=12 tgid=12 comm=curl direction=outbound dst=1.1.1.1"}, // not listed
		{"linux_process_exec", "dst=45.33.32.156"}, // not network
	}
	for _, l := range lines {
		w.Observe(tailer.Encode(l.logType, l.line))
	}
	if len(out.lines) != 4 {
		t.Fatalf("want 4 matches, got %d: %v", len(out.lines), out.lines)
	}
	first, win, ss := out.lines[0], out.lines[2], out.lines[3]
	if first["ip"] != "45.33.32.156" || first["cidr"] != "45.33.32.156/32" || first["blocked"] != true ||
		first["pid"] != "10" || first["image"] != "curl" || first["reason"] != "known C2" || first["mode"] != "block" {
		t.Fatalf("linux match: %v", first)
	}
	if out.lines[1]["ip"] != "8.8.4.77" || out.lines[1]["cidr"] != "8.8.4.0/24" {
		t.Fatalf("accept match: %v", out.lines[1])
	}
	if win["cidr"] != "2606:4700:4700::/48" || win["image"] != `C:\Users\a\evil.exe` || win["direction"] != "outbound" {
		t.Fatalf("windows match: %v", win)
	}
	if ss["pid"] != "777" || ss["image"] != "nc" || ss["telemetry"] != "linux_network_snapshot" {
		t.Fatalf("snapshot match: %v", ss)
	}

	// detect mode reports without claiming a block; the same process and address is reported once
	w.Update(list("detect", "45.33.32.156/32"))
	w.Observe(tailer.Encode("linux_network_connect", "pid=99 tgid=99 comm=wget direction=outbound dst=45.33.32.156"))
	w.Observe(tailer.Encode("linux_network_connect", "pid=99 tgid=99 comm=wget direction=outbound dst=45.33.32.156"))
	if len(out.lines) != 5 || out.lines[4]["blocked"] != false || out.lines[4]["mode"] != "detect" {
		t.Fatalf("detect: %v", out.lines[4:])
	}

	// off: nothing
	w.Update(list("off", "45.33.32.156/32"))
	w.Observe(tailer.Encode("linux_network_connect", "pid=100 tgid=100 dst=45.33.32.156"))
	if len(out.lines) != 5 {
		t.Fatal("mode off must not report")
	}
}

func TestWatcherRateLimit(t *testing.T) {
	out := &sink{}
	w := NewWatcher(out.push, nil)
	now := time.Unix(1_800_000_000, 0)
	w.now = func() time.Time { return now }
	w.Update(list("detect", "45.33.32.156/32"))
	for pid := 0; pid < maxPerMinute+30; pid++ {
		w.Observe(tailer.Encode("linux_network_connect", "tgid="+strconv.Itoa(pid)+" dst=45.33.32.156"))
	}
	if len(out.lines) != maxPerMinute {
		t.Fatalf("want %d reports in a minute, got %d", maxPerMinute, len(out.lines))
	}
	now = now.Add(time.Minute)
	w.Observe(tailer.Encode("linux_network_connect", "tgid=99999 dst=45.33.32.156"))
	if len(out.lines) != maxPerMinute+1 {
		t.Fatal("the next minute reports again")
	}
}
