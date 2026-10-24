package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/detect"
	"github.com/siem-platform/agent/internal/evidence"
	"github.com/siem-platform/agent/internal/tailer"
)

const (
	testAgentID = "11111111-1111-4111-8111-111111111111"
	testReceipt = "22222222-2222-4222-8222-222222222222"
)

func durableConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Agent.ID = testAgentID
	cfg.Evidence = config.EvidenceConfig{
		Enabled: true, Dir: filepath.Join(t.TempDir(), "evidence"),
		MaxBytes: 1 << 20, SegmentBytes: 64 << 10, ReservedBytes: 16 << 10, MaxEventBytes: 4096,
	}
	return cfg
}

func options(cfg *config.Config) evidence.Options {
	e := cfg.Evidence
	return evidence.Options{Dir: e.Dir, AgentID: cfg.Agent.ID, MaxBytes: e.MaxBytes,
		SegmentBytes: e.SegmentBytes, ReservedBytes: e.ReservedBytes, MaxEventBytes: e.MaxEventBytes}
}

// drain reopens the journal after shutdown and returns every unacknowledged event.
func drain(t *testing.T, cfg *config.Config) []evidence.Envelope {
	t.Helper()
	j, err := evidence.Open(options(cfg))
	if err != nil {
		t.Fatalf("journal not released on shutdown: %v", err)
	}
	defer j.Close()
	var out []evidence.Envelope
	for {
		e, ok, err := j.Peek(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return out
		}
		out = append(out, e)
		if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDurableRuntimeAdmitsProducerEntries(t *testing.T) {
	cfg := durableConfig(t)
	rt := openDurable(cfg, "web01")
	if rt.journal == nil {
		t.Fatal("journal did not open")
	}
	rt.buf.Push(tailer.Encode("linux_process_exec", "Image=/usr/bin/curl"))
	rt.shutdown() // drains the publisher before closing
	got := drain(t, cfg)
	if len(got) != 1 || got[0].LogType != "linux_process_exec" || got[0].RawMessage != "Image=/usr/bin/curl" ||
		got[0].Hostname != "web01" || got[0].AgentID != testAgentID {
		t.Fatalf("journal holds %+v", got)
	}
}

func TestDurableLocalDetectionObservesEachAdmissionOnceWhileOffline(t *testing.T) {
	cfg := durableConfig(t)
	rt := openDurable(cfg, "web01")
	rules, err := detect.ApplyEnabled(detect.DefaultRules(), []string{"ssh_bruteforce"}) // threshold 5
	if err != nil {
		t.Fatal(err)
	}
	rt.setDetector(detect.New(detect.Options{Rules: rules, Buffer: rt.buf}))
	// no sender: the server is unreachable, detection must still run
	for i := 0; i < 5; i++ {
		rt.buf.Push(tailer.Encode("linux_auth", "sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"))
	}
	// bridge offers are asynchronous: let all five and the detection land first
	// (a detection raised while shutdown drains the bridge is refused)
	waitFor(t, "admissions", func() bool { return rt.journal.Snapshot().QueuedEvents == 6 })
	rt.shutdown()

	var auth, detections []evidence.Envelope
	for _, e := range drain(t, cfg) {
		switch e.LogType {
		case "linux_auth":
			auth = append(auth, e)
		case "local_detection":
			detections = append(detections, e)
		}
	}
	if len(auth) != 5 || len(detections) != 1 {
		t.Fatalf("auth=%d detections=%d", len(auth), len(detections))
	}
	var d struct {
		Rule  string `json:"rule"`
		Count int    `json:"count"`
	}
	if err := json.Unmarshal([]byte(detections[0].RawMessage), &d); err != nil {
		t.Fatal(err)
	}
	// observed twice per event, the rule would fire at the third line instead
	if d.Rule != "ssh_bruteforce" || d.Count != 5 {
		t.Fatalf("detection %+v", d)
	}
}

func TestDurableModeBlocksCollectionWhenTheJournalCannotOpen(t *testing.T) {
	cfg := durableConfig(t)
	if err := os.WriteFile(cfg.Evidence.Dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := openDurable(cfg, "web01")
	if rt.journal != nil {
		t.Fatal("journal opened over a file")
	}
	rt.buf.Push(tailer.Encode("syslog", "line"))
	if dropped := rt.buf.ResetDropped(); dropped != 1 {
		t.Fatalf("blocked collection must show as dropped, got %d", dropped)
	}
	rt.startSender(client.New("http://127.0.0.1:1", "t"), func() bool { return true })
	if rt.sender.Load() != nil {
		t.Fatal("sender started without a journal")
	}
	rt.shutdown()
}

func TestDurableSenderWaitsForProtocolThenDelivers(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e evidence.Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol_version": 2, "event_id": e.EventID,
			"status": "accepted", "receipt_id": testReceipt})
	}))
	defer s.Close()

	cfg := durableConfig(t)
	rt := openDurable(cfg, "web01")
	var advertised atomic.Bool
	rt.startSender(client.New(s.URL, "agent-token"), advertised.Load)
	rt.buf.Push(tailer.Encode("syslog", "first"))
	time.Sleep(200 * time.Millisecond)
	if requests.Load() != 0 {
		t.Fatal("sent before the server advertised protocol 2")
	}
	advertised.Store(true)
	waitFor(t, "delivery", func() bool { return rt.journal.Snapshot().LastReceiptAt != nil })
	rt.shutdown()
	if left := drain(t, cfg); len(left) != 0 {
		t.Fatalf("delivered evidence still queued: %+v", left)
	}
}

func TestDurableStartupImportsTheLegacySpillOnce(t *testing.T) {
	cfg := durableConfig(t)
	cfg.Buffer.SpillPath = filepath.Join(t.TempDir(), "spill.log")
	spill := "linux_auth\x00/var/log/auth.log\x00Failed password\nsyslog\x00\x00two\x1elines\n"
	if err := os.WriteFile(cfg.Buffer.SpillPath, []byte(spill), 0o600); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ { // a second start must not import again
		rt := openDurable(cfg, "web01")
		rt.importLegacy(cfg.Buffer.SpillPath, cfg.Agent.ID, "web01")
		rt.shutdown()
	}
	got := drain(t, cfg)
	if len(got) != 2 || !got[0].LegacyImport || got[1].RawMessage != "two\nlines" {
		t.Fatalf("imported %+v", got)
	}
	if b, _ := os.ReadFile(cfg.Buffer.SpillPath); string(b) != spill {
		t.Fatal("the legacy spill was modified")
	}
}

func TestDurableShutdownStopsABlockedImport(t *testing.T) {
	cfg := durableConfig(t)
	cfg.Evidence.MaxBytes, cfg.Evidence.SegmentBytes, cfg.Evidence.ReservedBytes = 64<<10, 32<<10, 16<<10
	cfg.Buffer.SpillPath = filepath.Join(t.TempDir(), "spill.log")
	line := "syslog\x00\x00" + strings.Repeat("y", 300) + "\n"
	if err := os.WriteFile(cfg.Buffer.SpillPath, []byte(strings.Repeat(line, 400)), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := importRetry
	importRetry = 10 * time.Millisecond
	defer func() { importRetry = saved }()
	rt := openDurable(cfg, "web01")
	rt.importLegacy(cfg.Buffer.SpillPath, cfg.Agent.ID, "web01")
	if rt.importDone == nil {
		t.Fatal("a blocked import was not retried in the background")
	}
	if s := reportJSON(t, rt)["sources"].(map[string]any)["legacy-spill"].(map[string]any); s["reason"] != "migration_blocked" {
		t.Fatalf("health %v", s)
	}
	done := make(chan struct{})
	go func() { rt.shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited forever for the import")
	}
}

func reportJSON(t *testing.T, rt *durableRuntime) map[string]any {
	t.Helper()
	b, err := json.Marshal(rt.report())
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDurableReportKeepsCumulativeHealthAcrossRestarts(t *testing.T) {
	cfg := durableConfig(t)
	rt := openDurable(cfg, "web01")
	if err := rt.journal.RecordLoss(context.Background(), "file:/var/log/app.log", "oversize", 2, true); err != nil {
		t.Fatal(err)
	}
	r := reportJSON(t, rt)
	if r["mode"] != "durable" || r["version"] != float64(1) || r["unknown_gaps"] != float64(1) ||
		r["known_loss"].(map[string]any)["oversize"] != float64(2) {
		t.Fatalf("report %v", r)
	}
	for _, key := range []string{"known_loss", "pending_loss", "sources"} {
		if r[key] == nil { // the server expects objects, not null
			t.Fatalf("%s is null", key)
		}
	}
	rt.shutdown()

	// a failed heartbeat or a restart loses nothing: the counters are durable
	rt = openDurable(cfg, "web01")
	defer rt.shutdown()
	r = reportJSON(t, rt)
	if r["unknown_gaps"] != float64(1) || r["known_loss"].(map[string]any)["oversize"] != float64(2) {
		t.Fatalf("counters reset across restart: %v", r)
	}
	if r["sources"].(map[string]any)["file:/var/log/app.log"].(map[string]any)["state"] != "degraded" {
		t.Fatalf("source health %v", r["sources"])
	}
}

func TestDurableReportShowsTheSenderAndAnUnavailableJournal(t *testing.T) {
	cfg := durableConfig(t)
	rt := openDurable(cfg, "web01")
	rt.startSender(client.New("http://127.0.0.1:1", "t"), func() bool { return false })
	waitFor(t, "sender state", func() bool {
		s, _ := reportJSON(t, rt)["sender"].(map[string]any)
		return s != nil && s["state"] == "blocked" && s["reason"] == "protocol_unsupported"
	})
	rt.shutdown()

	broken := durableConfig(t)
	if err := os.WriteFile(broken.Evidence.Dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	down := openDurable(broken, "web01")
	r := reportJSON(t, down)
	if r["state"] != "degraded" || r["reason"] != "journal_unavailable" || r["mode"] != "durable" {
		t.Fatalf("unavailable journal reported as %v", r)
	}
}

func TestDurableShutdownLeavesUnsentEvidenceAndDropsLateOffers(t *testing.T) {
	cfg := durableConfig(t)
	rt := openDurable(cfg, "web01")
	rt.startSender(client.New("http://127.0.0.1:1", "t"), func() bool { return false })
	rt.buf.Push(tailer.Encode("syslog", "kept"))
	rt.shutdown()
	rt.buf.Push(tailer.Encode("syslog", "after shutdown")) // a producer that has not exited yet
	if dropped := rt.buf.ResetDropped(); dropped != 1 {
		t.Fatalf("late offer not counted as dropped: %d", dropped)
	}
	got := drain(t, cfg)
	if len(got) != 1 || got[0].RawMessage != "kept" {
		t.Fatalf("journal holds %+v", got)
	}
}
