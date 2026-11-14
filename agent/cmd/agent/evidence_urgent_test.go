package main

import (
	"context"
	"errors"
	"testing"

	"github.com/siem-platform/agent/internal/evidence"
	"github.com/siem-platform/agent/internal/mlscan"
	"github.com/siem-platform/agent/internal/ransomguard"
	"github.com/siem-platform/agent/internal/tailer"
)

type fakeAdmitter struct {
	submitErr error
	submitted []string
	offered   []string
}

func (f *fakeAdmitter) Submit(_ context.Context, d evidence.Draft) (evidence.Envelope, error) {
	f.submitted = append(f.submitted, d.LogType)
	return evidence.Envelope{}, f.submitErr
}

func (f *fakeAdmitter) TrySubmit(d evidence.Draft) error {
	f.offered = append(f.offered, d.LogType)
	return evidence.ErrBridgeFull // a telemetry burst filled the bridge
}

// Detections must not share the bridge with telemetry: with the bridge full,
// a ransomware or static ML detection is still admitted (the legacy queue's
// urgent lane, which durable mode did not have).
func TestDurableSinkAdmitsDetectionsDurably(t *testing.T) {
	f := &fakeAdmitter{}
	for _, lt := range []string{ransomguard.LogType, mlscan.LogType, "local_detection"} {
		if err := durableSink(f, tailer.Encode(lt, "x")); err != nil {
			t.Fatalf("%s: %v", lt, err)
		}
	}
	if err := durableSink(f, tailer.Encode("linux_process_exec", "x")); !errors.Is(err, evidence.ErrBridgeFull) {
		t.Fatalf("telemetry goes to the bridge: %v", err)
	}
	if len(f.submitted) != 3 || len(f.offered) != 1 || f.offered[0] != "linux_process_exec" {
		t.Fatalf("submitted %v, offered %v", f.submitted, f.offered)
	}
}

// A failed durable admission still reaches the bridge, so the loss is counted.
func TestDurableSinkFallsBackToTheBridge(t *testing.T) {
	f := &fakeAdmitter{submitErr: evidence.ErrFull}
	if err := durableSink(f, tailer.Encode(mlscan.LogType, "x")); !errors.Is(err, evidence.ErrBridgeFull) {
		t.Fatalf("fallback result: %v", err)
	}
	if len(f.offered) != 1 {
		t.Fatalf("not offered to the bridge: %v", f.offered)
	}
	f = &fakeAdmitter{submitErr: evidence.ErrPublisherStopped}
	if err := durableSink(f, tailer.Encode(mlscan.LogType, "x")); !errors.Is(err, evidence.ErrPublisherStopped) || len(f.offered) != 0 {
		t.Fatalf("stopped publisher: %v, offered %v", err, f.offered)
	}
}
