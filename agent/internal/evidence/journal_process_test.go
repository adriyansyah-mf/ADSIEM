package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
)

func TestJournalProcessHelper(t *testing.T) {
	mode := os.Getenv("SIEM_EVIDENCE_TEST_MODE")
	if mode == "" {
		return
	}
	o := Options{Dir: os.Getenv("SIEM_EVIDENCE_TEST_DIR"), AgentID: "11111111-1111-4111-8111-111111111111", MaxBytes: 1 << 20, SegmentBytes: 64 << 10, ReservedBytes: 16 << 10, MaxEventBytes: 4096}
	j, err := Open(o)
	if mode == "locked" {
		if j != nil {
			j.Close()
		}
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("subprocess lock: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatal(err)
	}
	// Deliberately exit without Close: success must depend on Append's flush.
	os.Exit(0)
}

func journalProcess(t *testing.T, o Options, mode string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestJournalProcessHelper$")
	cmd.Env = append(os.Environ(), "SIEM_EVIDENCE_TEST_MODE="+mode, "SIEM_EVIDENCE_TEST_DIR="+o.Dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child %s: %v\n%s", mode, err, output)
	}
}

func TestJournalLockAcrossProcesses(t *testing.T) {
	o := journalOptions(t)
	openJournal(t, o)
	journalProcess(t, o, "locked")
}

func TestAppendSurvivesAbruptProcessExit(t *testing.T) {
	o := journalOptions(t)
	journalProcess(t, o, "append")
	j := openJournal(t, o)
	e, ok, err := j.Peek(context.Background())
	if err != nil || !ok || e.RawMessage != "number=1" || e.Cursor == nil || e.Cursor.Offset != 42 {
		t.Fatalf("abrupt recovery: %#v %v %v", e, ok, err)
	}
}

func TestConcurrentAdmissionsSurviveRecovery(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	var wg sync.WaitGroup
	failures := make(chan error, 24)
	for i := range 24 {
		e := journalEvent(t, o)
		e.Cursor.Source = fmt.Sprintf("source-%d", i)
		wg.Add(1)
		go func() { defer wg.Done(); failures <- j.Append(context.Background(), e) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	for i := range 24 {
		if c, ok := j.Cursor(fmt.Sprintf("source-%d", i)); !ok || c.Offset != 42 {
			t.Fatalf("concurrent cursor %d lost: %#v %v", i, c, ok)
		}
	}
}
