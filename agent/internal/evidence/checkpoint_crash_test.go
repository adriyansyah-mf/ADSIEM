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
)

func compactCrashFixture(t *testing.T) (*Journal, []Envelope) {
	t.Helper()
	o := journalOptions(t)
	o.SegmentBytes = 4096
	o.MaxEventBytes = 2048
	j := openJournal(t, o)
	var events []Envelope
	for i := range 12 {
		e := journalEvent(t, o)
		e.RawMessage = strings.Repeat("x", 600)
		e.Cursor.Offset = int64(i + 1)
		if err := j.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if err := j.Hold(context.Background(), events[0].EventID, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := j.Quarantine(context.Background(), events[1].EventID, "invalid"); err != nil {
		t.Fatal(err)
	}
	for _, e := range events[2:11] {
		if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
	return j, events
}

func TestCompactCrashProcessHelper(t *testing.T) {
	encoded := os.Getenv("TASK3_CHECKPOINT_TEST_OPTIONS")
	if encoded == "" {
		return
	}
	var o Options
	if err := json.Unmarshal([]byte(encoded), &o); err != nil {
		t.Fatal(err)
	}
	boundary := os.Getenv("TASK3_CHECKPOINT_TEST_BOUNDARY")
	fault := func(operation, name string) error {
		if operation+"|"+name == boundary {
			os.Exit(91)
		}
		return nil
	}
	if os.Getenv("TASK3_CHECKPOINT_TEST_ACTION") == "recover" {
		j, err := openWithDependencies(o, journalDependencies{fault: fault})
		if j != nil {
			j.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("requested recovery crash boundary was not reached")
	}
	j, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	j.fault = fault
	var actionErr error
	switch os.Getenv("TASK3_CHECKPOINT_TEST_ACTION") {
	case "ack":
		e, ok, err := j.Peek(context.Background())
		if err != nil || !ok {
			t.Fatalf("ACK candidate: %v %v", ok, err)
		}
		actionErr = j.Ack(context.Background(), e.EventID, testReceipt)
	case "", "compact":
		actionErr = j.Compact(context.Background())
	default:
		t.Fatal("invalid child action")
	}
	if actionErr != nil {
		t.Fatal(actionErr)
	}
	t.Fatal("requested crash boundary was not reached")
}

func TestCompactCrashAtEveryPublicationAndDeletionBoundary(t *testing.T) {
	// Given a successful reference trace of every actual publication/removal.
	j, _ := compactCrashFixture(t)
	var boundaries []string
	j.fault = func(operation, name string) error { boundaries = append(boundaries, operation+"|"+name); return nil }
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(boundaries) < 30 {
		t.Fatalf("missing crash boundaries: %v", boundaries)
	}
	t.Logf("compaction crash boundaries=%d", len(boundaries))
	for i, boundary := range boundaries {
		t.Run(fmt.Sprintf("%02d-%s", i, boundary), func(t *testing.T) {
			store, events := compactCrashFixture(t)
			o := store.options
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCompactCrashProcessHelper$")
			cmd.Env = append(os.Environ(), "TASK3_CHECKPOINT_TEST_OPTIONS="+string(encoded), "TASK3_CHECKPOINT_TEST_BOUNDARY="+boundary)
			// When the process dies without Close at this individual boundary.
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 91 {
				t.Fatalf("crash boundary: %v\n%s", err, output)
			}
			store = openJournal(t, o)
			got, ok, err := store.Peek(context.Background())
			if err != nil || !ok || got.EventID != events[11].EventID {
				t.Fatalf("undelivered evidence after crash: %v %v", ok, err)
			}
			if c, ok := store.Cursor("syslog"); !ok || c.Offset != 12 {
				t.Fatalf("cursor after crash: %#v %v", c, ok)
			}
			h := store.Snapshot()
			if h.Held != 1 || h.Quarantined != 1 || h.QueuedEvents != 3 || h.LastReceiptAt == nil {
				t.Fatalf("health after crash: %#v", h)
			}
			retained := map[string]bool{}
			if err := store.walkEvents(context.Background(), func(e Envelope, p eventPosition) (bool, error) { retained[e.EventID] = true; return false, nil }); err != nil {
				t.Fatal(err)
			}
			if !retained[events[0].EventID] || !retained[events[1].EventID] {
				t.Fatal("terminal payload deleted across crash")
			}
			if err := store.Compact(context.Background()); err != nil {
				t.Fatal(err)
			}
			if store.used > o.MaxBytes {
				t.Fatal("crash recovery exceeded budget")
			}
		})
	}
}
