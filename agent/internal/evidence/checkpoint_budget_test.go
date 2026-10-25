package evidence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func controlDiskBytes(t *testing.T, j *Journal) (int64, int64) {
	t.Helper()
	names, err := j.dir.names()
	if err != nil {
		t.Fatal(err)
	}
	var total, control int64
	for _, name := range names {
		f, err := j.dir.open(name, os.O_RDONLY)
		if err != nil {
			t.Fatal(err)
		}
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		total += info.Size()
		if strings.HasPrefix(name, "checkpoint-") || strings.HasPrefix(name, "commit-") {
			control += info.Size()
		}
	}
	return total, control
}

func TestBudgetSparseReceiptsBoundPeakControlSpace(t *testing.T) {
	// Given tiny events with sparse out-of-order receipts in one partial segment.
	o := journalOptions(t)
	o.MaxBytes = 65536
	o.SegmentBytes = 32768
	o.ReservedBytes = 8192
	o.MaxEventBytes = 2048
	j := openJournal(t, o)
	var events []Envelope
	for range 60 {
		events = append(events, appendEvidence(t, j))
	}
	var peakTotal, peakControl int64
	j.fault = func(operation, name string) error {
		if operation == "after-namespace-sync" || operation == "after-delete-sync" {
			total, control := controlDiskBytes(t, j)
			if total > peakTotal {
				peakTotal = total
			}
			if control > peakControl {
				peakControl = control
			}
			if total > o.MaxBytes || control > o.ReservedBytes {
				t.Fatalf("peak quota violation: total=%d control=%d", total, control)
			}
		}
		return nil
	}
	// When sparse receipt spans converge, metadata shrinks before payload reclaim.
	for i := 1; i < len(events); i += 2 {
		if err := j.Ack(context.Background(), events[i].EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
	_, sparse := controlDiskBytes(t, j)
	for i := 2; i < len(events); i += 2 {
		if err := j.Ack(context.Background(), events[i].EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
	_, merged := controlDiskBytes(t, j)
	if merged >= sparse {
		t.Fatalf("partial metadata did not compact: sparse=%d merged=%d", sparse, merged)
	}
	if len(j.segments) != 1 || j.Snapshot().QueuedEvents != 1 {
		t.Fatal("control compaction changed retained payload")
	}
	t.Logf("peak_total=%d peak_control=%d sparse_control=%d merged_control=%d reserve=%d", peakTotal, peakControl, sparse, merged, o.ReservedBytes)
}

func BenchmarkCheckpointAdmissionReceiptCompaction(b *testing.B) {
	o := Options{Dir: filepath.Join(b.TempDir(), "journal"), AgentID: "11111111-1111-4111-8111-111111111111", MaxBytes: 1 << 20, SegmentBytes: 64 << 10, ReservedBytes: 16 << 10, MaxEventBytes: 4096}
	j, err := Open(o)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := j.Close(); err != nil {
			b.Error(err)
		}
	}()
	var namespaceSyncs int64
	var namespaceStarted time.Time
	var namespaceElapsed time.Duration
	j.fault = func(operation, name string) error {
		if operation == "before-namespace-sync" || operation == "before-delete-sync" {
			namespaceSyncs++
			namespaceStarted = time.Now()
		}
		if operation == "after-namespace-sync" || operation == "after-delete-sync" {
			namespaceElapsed += time.Since(namespaceStarted)
		}
		return nil
	}
	ctx := context.Background()
	b.ResetTimer()
	for range b.N {
		e, err := NewEnvelope(o.AgentID, "host", Draft{LogType: "syslog", RawMessage: "benchmark"}, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
		if err != nil {
			b.Fatal(err)
		}
		if err := j.Append(ctx, e); err != nil {
			b.Fatal(err)
		}
		if err := j.MarkAttempt(ctx, e.EventID, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)); err != nil {
			b.Fatal(err)
		}
		if err := j.Ack(ctx, e.EventID, testReceipt); err != nil {
			b.Fatal(err)
		}
		if err := j.Compact(ctx); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(namespaceSyncs)/float64(b.N), "control-namespace-syncs/op")
	b.ReportMetric(float64(namespaceElapsed.Nanoseconds())/float64(namespaceSyncs), "ns/control-namespace-sync")
}
