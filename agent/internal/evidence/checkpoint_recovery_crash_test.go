package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func pendingCleanupFixture(t *testing.T) (Options, []Envelope) {
	t.Helper()
	j, events := compactCrashFixture(t)
	o := j.options
	j.fault = func(operation, name string) error {
		if operation == "after-publication" {
			return os.ErrPermission
		}
		return nil
	}
	if err := j.Compact(context.Background()); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("pending cleanup fixture: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	return o, events
}

func TestCompactRecoveryCleanupSurvivesEveryRemovalCrash(t *testing.T) {
	// Given a committed generation whose old files have not been cleaned yet.
	o, _ := pendingCleanupFixture(t)
	var boundaries []string
	j, err := openWithDependencies(o, journalDependencies{fault: func(operation, name string) error { boundaries = append(boundaries, operation+"|"+name); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if len(boundaries) < 12 {
		t.Fatalf("missing recovery cleanup boundaries: %v", boundaries)
	}
	t.Logf("recovery cleanup crash boundaries=%d", len(boundaries))
	for _, boundary := range boundaries {
		t.Run(strings.ReplaceAll(boundary, "|", "-"), func(t *testing.T) {
			o, events := pendingCleanupFixture(t)
			encoded, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCompactCrashProcessHelper$")
			cmd.Env = append(os.Environ(), "TASK3_CHECKPOINT_TEST_OPTIONS="+string(encoded), "TASK3_CHECKPOINT_TEST_BOUNDARY="+boundary, "TASK3_CHECKPOINT_TEST_ACTION=recover")
			// When recovery itself dies while retiring each old file, retry it.
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 91 {
				t.Fatalf("recovery crash: %v\n%s", err, output)
			}
			store := openJournal(t, o)
			next, ok, err := store.Peek(context.Background())
			if err != nil || !ok || next.EventID != events[11].EventID {
				t.Fatalf("recovery replay: %v %v", ok, err)
			}
			if h := store.Snapshot(); h.Held != 1 || h.Quarantined != 1 || h.QueuedEvents != 3 {
				t.Fatalf("recovery lost terminal state: %#v", h)
			}
		})
	}
}
