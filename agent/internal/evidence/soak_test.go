package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"
)

// TestSustainedCapture is the sustained-capture measurement for
// docs/operations/agent-evidence-validation.md, skipped unless asked for:
//
//	EVIDENCE_SOAK=1h EVIDENCE_SOAK_RATE=200 EVIDENCE_SOAK_REPORT=soak.json \
//	  go test ./agent/internal/evidence -run TestSustainedCapture -timeout 0 -v
//
// One producer appends at RATE events/s (each a durable admission) while a
// drainer delivers in batches the way the batch sender does, so the journal
// stays near steady state. The JSON report has throughput, append latency
// percentiles, process CPU, peak heap and the journal's bytes on disk,
// sampled every minute. EVIDENCE_SOAK_DIR places the journal (default: a
// temp dir; give a real disk, /tmp may be tmpfs).
func TestSustainedCapture(t *testing.T) {
	duration, err := time.ParseDuration(os.Getenv("EVIDENCE_SOAK"))
	if err != nil || duration <= 0 {
		t.Skip("set EVIDENCE_SOAK (e.g. 1h) to run the sustained capture")
	}
	rate := 200.0
	if v, err := strconv.ParseFloat(os.Getenv("EVIDENCE_SOAK_RATE"), 64); err == nil && v > 0 {
		rate = v
	}
	base := os.Getenv("EVIDENCE_SOAK_DIR")
	if base == "" {
		base = t.TempDir()
	}
	o := Options{Dir: filepath.Join(base, fmt.Sprintf("soak-%d", time.Now().UnixNano())),
		AgentID: "11111111-1111-4111-8111-111111111111",
		MaxBytes: 1 << 30, SegmentBytes: 16 << 20, ReservedBytes: 16 << 20, MaxEventBytes: 1 << 20}
	j, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	defer os.RemoveAll(o.Dir)

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	drained := make(chan int64, 1)
	go func() { drained <- drain(ctx, t, j) }()

	var latencies []time.Duration
	var samples []soakSample
	start := time.Now()
	nextSample := start.Add(time.Minute)
	interval := time.Duration(float64(time.Second) / rate)
	var appended int64
	for n := 0; ctx.Err() == nil; n++ {
		due := start.Add(time.Duration(n) * interval)
		if d := time.Until(due); d > 0 {
			time.Sleep(d)
		}
		e := soakEvent(t, o, n)
		began := time.Now()
		if err := j.Append(context.Background(), e); err != nil {
			t.Fatalf("append %d: %v", n, err)
		}
		latencies = append(latencies, time.Since(began))
		appended++
		if time.Now().After(nextSample) {
			samples = append(samples, sample(j, o.Dir, start, appended))
			nextSample = nextSample.Add(time.Minute)
		}
	}
	delivered := <-drained
	samples = append(samples, sample(j, o.Dir, start, appended))
	elapsed := time.Since(start)

	sort.Slice(latencies, func(a, b int) bool { return latencies[a] < latencies[b] })
	pct := func(p float64) float64 {
		return float64(latencies[int(p*float64(len(latencies)-1))].Microseconds())
	}
	var peakHeap, peakDisk int64
	for _, s := range samples {
		peakHeap, peakDisk = max(peakHeap, s.HeapBytes), max(peakDisk, s.DiskBytes)
	}
	host, _ := os.Hostname()
	report := map[string]any{
		"os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "go": runtime.Version(), "host": host,
		"journal_dir": o.Dir, "duration_s": elapsed.Seconds(), "target_rate": rate,
		"appended": appended, "delivered": delivered, "events_per_s": float64(appended) / elapsed.Seconds(),
		"append_p50_us": pct(0.50), "append_p95_us": pct(0.95), "append_p99_us": pct(0.99),
		"cpu_seconds": processCPUSeconds(), "cpu_percent_of_one_core": 100 * processCPUSeconds() / elapsed.Seconds(),
		"peak_heap_bytes": peakHeap, "peak_rss_bytes": peakRSSBytes(), "peak_disk_bytes": peakDisk, "samples": samples,
	}
	b, _ := json.MarshalIndent(report, "", "  ")
	if path := os.Getenv("EVIDENCE_SOAK_REPORT"); path != "" {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%s", b)
	if delivered < appended*9/10 {
		t.Fatalf("drainer fell behind: delivered %d of %d", delivered, appended)
	}
}

type soakSample struct {
	ElapsedS  float64 `json:"elapsed_s"`
	Appended  int64   `json:"appended"`
	Queued    int64   `json:"queued_events"`
	Indexed   int64   `json:"indexed_events"`
	HeapBytes int64   `json:"heap_bytes"`
	DiskBytes int64   `json:"disk_bytes"`
	CPUs      float64 `json:"cpu_seconds"`
}

func sample(j *Journal, dir string, start time.Time, appended int64) soakSample {
	h := j.Snapshot()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	var disk int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				disk += info.Size()
			}
		}
		return nil
	})
	return soakSample{ElapsedS: time.Since(start).Seconds(), Appended: appended, Queued: h.QueuedEvents,
		Indexed: h.IndexedEvents, HeapBytes: int64(m.HeapAlloc), DiskBytes: disk, CPUs: processCPUSeconds()}
}


func soakEvent(t *testing.T, o Options, n int) Envelope {
	e, err := NewEnvelope(o.AgentID, "soak-host", Draft{LogType: "linux_auth", Location: "/var/log/auth.log",
		RawMessage: fmt.Sprintf("Oct 25 10:00:00 host sshd[%d]: Failed password for invalid user admin from 203.0.113.%d port 52044 ssh2", n, n%250),
		Cursor:     &Cursor{Source: "file:/var/log/auth.log", Generation: "soak", Identity: "1:2", Offset: int64(n + 1)}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// drain delivers like the batch sender (and compacts like it, every minute)
// until ctx ends, then returns how many events it acknowledged.
func drain(ctx context.Context, t *testing.T, j *Journal) int64 {
	var delivered int64
	compacted := time.Now()
	for ctx.Err() == nil {
		batch, err := j.PeekBatch(ctx, sendBatchEvents, sendBatchBytes)
		if err != nil {
			if ctx.Err() == nil {
				t.Errorf("peek: %v", err)
			}
			break
		}
		if len(batch) == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ids := make([]string, len(batch))
		receipts := make([]Receipt, len(batch))
		for i, e := range batch {
			ids[i] = e.EventID
			receipts[i] = Receipt{EventID: e.EventID, ReceiptID: "22222222-2222-4222-8222-222222222222"}
		}
		if err := j.MarkAttempts(context.Background(), ids, time.Now()); err != nil {
			t.Errorf("mark: %v", err)
			break
		}
		if err := j.AckBatch(context.Background(), receipts); err != nil {
			t.Errorf("ack: %v", err)
			break
		}
		delivered += int64(len(batch))
		if time.Since(compacted) >= time.Minute {
			if err := j.Compact(context.Background()); err != nil {
				t.Errorf("compact: %v", err)
			}
			compacted = time.Now()
		}
	}
	return delivered
}
