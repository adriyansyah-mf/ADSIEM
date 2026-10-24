package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/evidence"
)

const secretPayload = "SECRET-PAYLOAD password=hunter2"

// parkedJournal prepares a stopped agent's journal: one held, one quarantined
// and one pending event, all carrying secretPayload.
func parkedJournal(t *testing.T) (*config.Config, string, string) {
	t.Helper()
	cfg := durableConfig(t)
	j, err := evidence.Open(options(cfg))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var ids []string
	for i := 0; i < 3; i++ {
		e, err := evidence.NewEnvelope(testAgentID, "web01", evidence.Draft{LogType: "linux_auth", RawMessage: secretPayload,
			Cursor: &evidence.Cursor{Source: "file:/var/log/auth.log", Generation: "g", Identity: "1:2", Offset: int64(i + 1)}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.EventID)
	}
	if err := j.MarkAttempt(ctx, ids[0], time.Now().Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := j.Hold(ctx, ids[0], "receipt_uncertainty_window"); err != nil {
		t.Fatal(err)
	}
	if err := j.Quarantine(ctx, ids[1], "rejected_status_422"); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	return cfg, ids[0], ids[1]
}

func asOperator(t *testing.T) {
	t.Helper()
	saved := checkOperator
	checkOperator = func() error { return nil }
	t.Cleanup(func() { checkOperator = saved })
}

func runCmd(t *testing.T, cfg *config.Config, c evidenceCommand) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runEvidenceCommand(cfg, c, &out)
	return out.String(), err
}

func TestEvidenceListShowsMetadataNeverPayload(t *testing.T) {
	asOperator(t)
	cfg, held, quarantined := parkedJournal(t)
	out, err := runCmd(t, cfg, evidenceCommand{list: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{held, quarantined, "held", "quarantined", "receipt_uncertainty_window",
		"rejected_status_422", "1 event(s) waiting for delivery, 2 held or quarantined"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output misses %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SECRET") || strings.Contains(out, "hunter2") {
		t.Fatalf("list echoed raw evidence:\n%s", out)
	}
}

func TestEvidenceDiscardNeedsAReasonAndKeepsDataWithout(t *testing.T) {
	asOperator(t)
	cfg, _, quarantined := parkedJournal(t)
	if _, err := runCmd(t, cfg, evidenceCommand{discard: quarantined, reason: "  "}); err == nil || !strings.Contains(err.Error(), "-reason") {
		t.Fatalf("discard without a reason: %v", err)
	}
	out, _ := runCmd(t, cfg, evidenceCommand{list: true})
	if !strings.Contains(out, quarantined) {
		t.Fatal("discard without a reason removed data")
	}
}

func TestEvidenceReleaseOfHeldNeedsConsent(t *testing.T) {
	asOperator(t)
	cfg, held, _ := parkedJournal(t)
	_, err := runCmd(t, cfg, evidenceCommand{release: held, reason: "server restored"})
	if err == nil || !strings.Contains(err.Error(), "-yes") || !strings.Contains(err.Error(), "repeat its detections") {
		t.Fatalf("held release without -yes: %v", err)
	}
	out, err := runCmd(t, cfg, evidenceCommand{release: held, reason: "server restored", yes: true})
	if err != nil || !strings.Contains(out, "released "+held) {
		t.Fatalf("release: %q %v", out, err)
	}
	out, _ = runCmd(t, cfg, evidenceCommand{list: true})
	if !strings.Contains(out, "2 event(s) waiting for delivery, 1 held or quarantined") ||
		!strings.Contains(out, "release "+held+" (was held): server restored") {
		t.Fatalf("after release:\n%s", out)
	}
}

func TestEvidenceDiscardIsAudited(t *testing.T) {
	asOperator(t)
	cfg, _, quarantined := parkedJournal(t)
	if out, err := runCmd(t, cfg, evidenceCommand{discard: quarantined, reason: "malformed test data"}); err != nil || !strings.Contains(out, "discarded") {
		t.Fatalf("discard: %q %v", out, err)
	}
	out, _ := runCmd(t, cfg, evidenceCommand{list: true})
	if strings.Contains(out, quarantined+"  quarantined") || !strings.Contains(out, "discard "+quarantined+" (was quarantined): malformed test data") {
		t.Fatalf("after discard:\n%s", out)
	}
	if _, err := runCmd(t, cfg, evidenceCommand{discard: quarantined, reason: "again"}); err == nil {
		t.Fatal("second discard succeeded")
	}
}

func TestEvidenceCommandsNeedTheAgentStoppedAndAnOperator(t *testing.T) {
	cfg, _, quarantined := parkedJournal(t)
	saved := checkOperator
	checkOperator = func() error { return errors.New("run as root") }
	_, err := runCmd(t, cfg, evidenceCommand{list: true})
	checkOperator = saved
	if err == nil || err.Error() != "run as root" {
		t.Fatalf("non-operator: %v", err)
	}

	asOperator(t)
	j, err := evidence.Open(options(cfg)) // the running agent owns the journal
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := runCmd(t, cfg, evidenceCommand{discard: quarantined, reason: "x"}); err == nil || !strings.Contains(err.Error(), "stop the service") {
		t.Fatalf("locked journal: %v", err)
	}
}

func TestEvidenceCommandDoesNotCreateAJournal(t *testing.T) {
	asOperator(t)
	cfg := durableConfig(t)
	if _, err := runCmd(t, cfg, evidenceCommand{list: true}); err == nil || !strings.Contains(err.Error(), "no evidence journal") {
		t.Fatalf("missing journal: %v", err)
	}
	if _, err := os.Stat(cfg.Evidence.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("list created a journal directory")
	}
}
