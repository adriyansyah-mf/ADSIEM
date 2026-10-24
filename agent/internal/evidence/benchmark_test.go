package evidence

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Measurements for docs/operations/agent-evidence-validation.md. Run with
//
//	go test ./agent/internal/evidence -bench . -benchmem -run '^$'
//
// No target is asserted: the numbers are published as measured.

const benchEvents = 10_000

// benchOptions is a production-shaped journal (default budgets) in a temp dir.
func benchOptions(b *testing.B) Options {
	return Options{Dir: filepath.Join(b.TempDir(), "journal"), AgentID: "11111111-1111-4111-8111-111111111111",
		MaxBytes: 1 << 30, SegmentBytes: 16 << 20, ReservedBytes: 16 << 20, MaxEventBytes: 1 << 20}
}

func benchEvent(b *testing.B, o Options, i int) Envelope {
	e, err := NewEnvelope(o.AgentID, "bench-host", Draft{LogType: "linux_auth", Location: "/var/log/auth.log",
		RawMessage: fmt.Sprintf("Oct 25 10:00:00 host sshd[%d]: Failed password for invalid user admin from 203.0.113.%d port 52044 ssh2", i, i%250),
		Cursor:     &Cursor{Source: "file:/var/log/auth.log", Generation: "bench", Identity: "1:2", Offset: int64(i + 1)}}, time.Now())
	if err != nil {
		b.Fatal(err)
	}
	return e
}

// fill appends n events and returns their IDs.
func fill(b *testing.B, j *Journal, o Options, n int) []string {
	ids := make([]string, n)
	for i := range n {
		e := benchEvent(b, o, i)
		if err := j.Append(context.Background(), e); err != nil {
			b.Fatal(err)
		}
		ids[i] = e.EventID
	}
	return ids
}

// BenchmarkAppendSync is one durable admission: frame write plus flush.
// Reports p50/p95 per append in addition to ns/op.
func BenchmarkAppendSync(b *testing.B) {
	o := benchOptions(b)
	j, err := Open(o)
	if err != nil {
		b.Fatal(err)
	}
	defer j.Close()
	events := make([]Envelope, b.N)
	for i := range events {
		events[i] = benchEvent(b, o, i)
	}
	latencies := make([]time.Duration, b.N)
	b.ResetTimer()
	for i := range b.N {
		start := time.Now()
		if err := j.Append(context.Background(), events[i]); err != nil {
			b.Fatal(err)
		}
		latencies[i] = time.Since(start)
	}
	b.StopTimer()
	sort.Slice(latencies, func(a, c int) bool { return latencies[a] < latencies[c] })
	b.ReportMetric(float64(latencies[len(latencies)/2].Microseconds()), "p50-µs")
	b.ReportMetric(float64(latencies[len(latencies)*95/100].Microseconds()), "p95-µs")
}

// BenchmarkRecover10k opens a journal holding 10,000 unacknowledged events.
func BenchmarkRecover10k(b *testing.B) {
	o := benchOptions(b)
	j, err := Open(o)
	if err != nil {
		b.Fatal(err)
	}
	fill(b, j, o, benchEvents)
	if err := j.Close(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		j, err := Open(o)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := j.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// BenchmarkSnapshot10k is one health snapshot of a 10,000-event backlog; the
// journal lock is held for all of it, so appends wait this long.
func BenchmarkSnapshot10k(b *testing.B) {
	o := benchOptions(b)
	j, err := Open(o)
	if err != nil {
		b.Fatal(err)
	}
	defer j.Close()
	fill(b, j, o, benchEvents)
	b.ResetTimer()
	for range b.N {
		if h := j.Snapshot(); h.QueuedEvents != benchEvents {
			b.Fatalf("queued %d", h.QueuedEvents)
		}
	}
}

// BenchmarkReplay10k delivers a 10,000-event backlog the way the sender does:
// Peek, mark the attempt, Ack, until empty. One op is the whole backlog.
func BenchmarkReplay10k(b *testing.B) {
	for range b.N {
		b.StopTimer()
		o := benchOptions(b)
		j, err := Open(o)
		if err != nil {
			b.Fatal(err)
		}
		fill(b, j, o, benchEvents)
		ctx := context.Background()
		b.StartTimer()
		delivered := 0
		for {
			e, ok, err := j.Peek(ctx)
			if err != nil {
				b.Fatal(err)
			}
			if !ok {
				break
			}
			if err := j.MarkAttempt(ctx, e.EventID, time.Now()); err != nil {
				b.Fatal(err)
			}
			if err := j.Ack(ctx, e.EventID, "22222222-2222-4222-8222-222222222222"); err != nil {
				b.Fatal(err)
			}
			delivered++
		}
		b.StopTimer()
		if delivered != benchEvents {
			b.Fatalf("delivered %d", delivered)
		}
		b.ReportMetric(float64(delivered), "events")
		if err := j.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// BenchmarkReplayBatch10k is BenchmarkReplay10k the way the batch sender does
// it: PeekBatch (200 events / 2 MiB), one MarkAttempts and one AckBatch each.
func BenchmarkReplayBatch10k(b *testing.B) {
	for range b.N {
		b.StopTimer()
		o := benchOptions(b)
		j, err := Open(o)
		if err != nil {
			b.Fatal(err)
		}
		fill(b, j, o, benchEvents)
		ctx := context.Background()
		b.StartTimer()
		delivered := 0
		for {
			batch, err := j.PeekBatch(ctx, sendBatchEvents, sendBatchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if len(batch) == 0 {
				break
			}
			ids := make([]string, len(batch))
			receipts := make([]Receipt, len(batch))
			for i, e := range batch {
				ids[i] = e.EventID
				receipts[i] = Receipt{EventID: e.EventID, ReceiptID: "22222222-2222-4222-8222-222222222222"}
			}
			if err := j.MarkAttempts(ctx, ids, time.Now()); err != nil {
				b.Fatal(err)
			}
			if err := j.AckBatch(ctx, receipts); err != nil {
				b.Fatal(err)
			}
			delivered += len(batch)
		}
		b.StopTimer()
		if delivered != benchEvents {
			b.Fatalf("delivered %d", delivered)
		}
		b.ReportMetric(float64(delivered), "events")
		if err := j.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// BenchmarkCompact10k reclaims 10,000 acknowledged events.
func BenchmarkCompact10k(b *testing.B) {
	for range b.N {
		b.StopTimer()
		o := benchOptions(b)
		o.SegmentBytes = 256 << 10 // several segments, so compaction deletes files
		o.MaxEventBytes = 64 << 10 // must fit a segment
		j, err := Open(o)
		if err != nil {
			b.Fatal(err)
		}
		ids := fill(b, j, o, benchEvents)
		ctx := context.Background()
		for _, id := range ids {
			if err := j.Ack(ctx, id, "22222222-2222-4222-8222-222222222222"); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		if err := j.Compact(ctx); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := j.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}
