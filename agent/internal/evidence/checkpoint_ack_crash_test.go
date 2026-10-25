package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func ackCrashFixture(t *testing.T) (*Journal, []Envelope) {
	t.Helper()
	j := openJournal(t, journalOptions(t))
	events := []Envelope{appendEvidence(t, j), appendEvidence(t, j)}
	if err := j.MarkAttempt(context.Background(), events[0].EventID, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordLoss(context.Background(), "syslog", "rotation_gap", 2, true); err != nil {
		t.Fatal(err)
	}
	return j, events
}

func TestAckCrashAtEveryCheckpointBoundary(t *testing.T) {
	// Given one complete publication trace with an older committed generation.
	j, events := ackCrashFixture(t)
	var boundaries []string
	j.fault = func(operation, name string) error { boundaries = append(boundaries, operation+"|"+name); return nil }
	if err := j.Ack(context.Background(), events[0].EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	if len(boundaries) < 26 {
		t.Fatalf("missing ACK crash boundaries: %v", boundaries)
	}
	t.Logf("ACK crash boundaries=%d", len(boundaries))
	for i, boundary := range boundaries {
		t.Run(fmt.Sprintf("%02d-%s", i, boundary), func(t *testing.T) {
			store, events := ackCrashFixture(t)
			o := store.options
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCompactCrashProcessHelper$")
			cmd.Env = append(os.Environ(), "TASK3_CHECKPOINT_TEST_OPTIONS="+string(encoded), "TASK3_CHECKPOINT_TEST_BOUNDARY="+boundary, "TASK3_CHECKPOINT_TEST_ACTION=ack")
			// When the process dies at each individual checkpoint boundary.
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 91 {
				t.Fatalf("ACK crash: %v\n%s", err, output)
			}
			store = openJournal(t, o)
			e, ok, err := store.Peek(context.Background())
			if err != nil || !ok {
				t.Fatalf("ACK restart: %v %v", ok, err)
			}
			// A complete marker becomes visible after its write on process exit;
			// before that point only the predecessor generation can be recovered.
			parts := strings.SplitN(boundary, "|", 2)
			operation, name := parts[0], parts[1]
			committed := strings.HasPrefix(name, "commit-00000000000000000003") && operation != "before-publication" && operation != "before-create" && operation != "after-create" && operation != "before-write"
			if strings.Contains(operation, "remove") || strings.Contains(operation, "delete-sync") {
				committed = true
			}
			want := events[0].EventID
			if committed {
				want = events[1].EventID
			}
			if e.EventID != want {
				t.Fatalf("publication selected wrong generation at %s: got %s want %s", boundary, e.EventID, want)
			}
			h := store.Snapshot()
			if h.KnownLoss["rotation_gap"] != 2 || h.UnknownGaps != 1 {
				t.Fatalf("predecessor counters lost: %#v", h)
			}
			if !committed {
				at, ok, err := store.FirstAttempt(context.Background(), events[0].EventID)
				if err != nil || !ok || at.Year() != 2026 || at.Month() != 1 || at.Day() != 1 {
					t.Fatalf("attempt after unpublished ACK: %v %v %v", at, ok, err)
				}
			}
		})
	}
}
