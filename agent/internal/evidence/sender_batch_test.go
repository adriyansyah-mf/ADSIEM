package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/client"
)

type batchHandler func(events []Envelope) (int, []batchResult)

// newBatchFixture is newSenderFixture with n events and a server that answers
// the batch endpoint through h; any request elsewhere fails the test.
func newBatchFixture(t *testing.T, n int, h batchHandler) (*Sender, *Journal, []string, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != BatchPath {
			t.Errorf("request to %s, want %s", r.URL.Path, BatchPath)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ProtocolVersion != 2 {
			t.Errorf("bad batch request: %v %+v", err, req)
		}
		code, results := h(req.Events)
		w.WriteHeader(code)
		if results != nil {
			_ = json.NewEncoder(w).Encode(batchResponse{ProtocolVersion: 2, Results: results})
		}
	}))
	t.Cleanup(s.Close)
	j := openJournal(t, journalOptions(t))
	ids := make([]string, n)
	for i := range ids {
		e := journalEvent(t, j.options)
		if err := j.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		ids[i] = e.EventID
	}
	sender := &Sender{
		Journal: j, Transport: client.New(s.URL, "test-token"),
		SupportsV2: func() bool { return true }, BatchMax: func() int { return 500 },
		Jitter: func(d time.Duration) time.Duration { return d },
	}
	return sender, j, ids, &calls
}

func acceptAll(events []Envelope) (int, []batchResult) {
	results := make([]batchResult, len(events))
	for i, e := range events {
		results[i] = batchResult{EventID: e.EventID, Status: "accepted", ReceiptID: testReceipt}
	}
	return http.StatusOK, results
}

func idle(t *testing.T, j *Journal) {
	t.Helper()
	if _, ok, err := j.Peek(context.Background()); err != nil || ok {
		t.Fatalf("evidence left to send: ok=%v err=%v", ok, err)
	}
}

func TestBatchSenderAcksWholeBatchInOneRequest(t *testing.T) {
	sender, j, _, calls := newBatchFixture(t, 25, acceptAll)
	if err := sender.Step(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("%d requests for one batch", calls.Load())
	}
	idle(t, j)
	if err := sender.Step(context.Background(), time.Now().UTC()); !errors.Is(err, ErrIdle) {
		t.Fatalf("want idle, got %v", err)
	}
}

func TestBatchSenderAppliesPerEventResults(t *testing.T) {
	sender, j, ids, _ := newBatchFixture(t, 3, func(events []Envelope) (int, []batchResult) {
		return http.StatusOK, []batchResult{
			{EventID: events[0].EventID, Status: "duplicate", ReceiptID: testReceipt},
			{EventID: events[1].EventID, Status: "rejected", Code: http.StatusConflict},
			{EventID: events[2].EventID, Status: "retry", Code: http.StatusTooManyRequests},
		}
	})
	retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
	retained(t, j, ids[2]) // the retried one is next; acked and quarantined are not
	if h := j.Snapshot(); h.Quarantined != 1 {
		t.Fatalf("rejected event not quarantined: %+v", h)
	}
	if err := j.Ack(context.Background(), ids[1], testReceipt); !errors.Is(err, ErrTerminal) {
		t.Fatalf("quarantined event can be acked: %v", err)
	}
}

func TestBatchSenderAcksNothingForAnUnmatchedResponse(t *testing.T) {
	cases := map[string]func([]Envelope) []batchResult{
		"missing result": func(ev []Envelope) []batchResult {
			_, r := acceptAll(ev)
			return r[:len(r)-1]
		},
		"reordered": func(ev []Envelope) []batchResult {
			_, r := acceptAll(ev)
			r[0], r[1] = r[1], r[0]
			return r
		},
		"bad receipt": func(ev []Envelope) []batchResult {
			_, r := acceptAll(ev)
			r[1].ReceiptID = "not-a-uuid"
			return r
		},
		"unknown status": func(ev []Envelope) []batchResult {
			_, r := acceptAll(ev)
			r[0].Status = "ok"
			return r
		},
		"rejected with a retryable code": func(ev []Envelope) []batchResult {
			_, r := acceptAll(ev)
			r[0] = batchResult{EventID: ev[0].EventID, Status: "rejected", Code: http.StatusServiceUnavailable}
			return r
		},
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			sender, j, ids, _ := newBatchFixture(t, 3, func(ev []Envelope) (int, []batchResult) {
				return http.StatusOK, mangle(ev)
			})
			if re := retryOf(t, sender.Step(context.Background(), time.Now().UTC())); re.Reason != "unconfirmed_response" {
				t.Fatalf("reason %q", re.Reason)
			}
			retained(t, j, ids[0])
			if h := j.Snapshot(); h.Quarantined != 0 {
				t.Fatalf("unmatched response changed state: %+v", h)
			}
		})
	}
}

func TestBatchSenderSplitsARefusedRequestToIsolateTheBadEvent(t *testing.T) {
	var bad string
	sender, j, ids, _ := newBatchFixture(t, 8, func(events []Envelope) (int, []batchResult) {
		for _, e := range events {
			if e.EventID == bad {
				return http.StatusUnprocessableEntity, nil
			}
		}
		return acceptAll(events)
	})
	bad = ids[5]
	for i := 0; i < 20; i++ {
		err := sender.Step(context.Background(), time.Now().UTC())
		if errors.Is(err, ErrIdle) {
			break
		}
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	idle(t, j)
	if h := j.Snapshot(); h.Quarantined != 1 {
		t.Fatalf("want only the bad event quarantined: %+v", h)
	}
	if err := j.Ack(context.Background(), bad, testReceipt); !errors.Is(err, ErrTerminal) {
		t.Fatalf("bad event was not the one quarantined: %v", err)
	}
}

func TestBatchSenderRetriesWithoutLosingEvidence(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		sender, j, ids, _ := newBatchFixture(t, 2, func([]Envelope) (int, []batchResult) { return code, nil })
		retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
		retained(t, j, ids[0])
	}
}

func TestBatchSenderLostResponseRetriesAsDuplicates(t *testing.T) {
	var calls int
	sender, j, _, _ := newBatchFixture(t, 4, func(events []Envelope) (int, []batchResult) {
		calls++
		if calls == 1 {
			return http.StatusBadGateway, nil // committed, but the response was lost
		}
		_, r := acceptAll(events)
		for i := range r {
			r[i].Status = "duplicate"
		}
		return http.StatusOK, r
	})
	retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
	if err := sender.Step(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	idle(t, j)
	if h := j.Snapshot(); h.Retries != 4 {
		t.Fatalf("each resend should count one retry: %+v", h)
	}
}

func TestSenderWithoutBatchSupportUsesTheSingleEndpoint(t *testing.T) {
	var path string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		var e Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(receiptFor(e.EventID, "accepted")))
	}))
	defer s.Close()
	sender, j, _ := newSenderFixture(t, s.URL)
	sender.BatchMax = func() int { return 0 }
	if err := sender.Step(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if path != SendPath {
		t.Fatalf("posted to %s", path)
	}
	idle(t, j)
}

// A batch needs one attempt record per event in the checkpoint. With a small
// control reserve a full batch does not fit: the sender must narrow the batch
// and keep delivering, not retry the same oversized batch forever.
func TestBatchSenderNarrowsWhenTheControlReserveCannotHoldABatch(t *testing.T) {
	sender, j, _, calls := newBatchFixture(t, 200, acceptAll) // journalOptions: 16 KiB reserve
	for i := 0; i < 100; i++ {
		err := sender.Step(context.Background(), time.Now().UTC())
		if errors.Is(err, ErrIdle) {
			break
		}
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	idle(t, j)
	if calls.Load() < 2 {
		t.Fatalf("delivered in %d request(s): the batch was never narrowed", calls.Load())
	}
}
