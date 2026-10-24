package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/client"
)

// newSenderFixture opens a real temp journal, admits one envelope and builds a
// Sender over the real agent HTTP client. Backoff jitter is the identity.
func newSenderFixture(t *testing.T, url string) (*Sender, *Journal, string) {
	t.Helper()
	j := openJournal(t, journalOptions(t))
	e := journalEvent(t, j.options)
	if err := j.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	s := &Sender{
		Journal:    j,
		Transport:  client.New(url, "test-token"),
		SupportsV2: func() bool { return true },
		Jitter:     func(d time.Duration) time.Duration { return d },
	}
	return s, j, e.EventID
}

func receiptFor(eventID, status string) string {
	b, _ := json.Marshal(map[string]any{"protocol_version": 2, "event_id": eventID, "status": status, "receipt_id": testReceipt})
	return string(b)
}

// retained asserts the event is still the next one to send.
func retained(t *testing.T, j *Journal, id string) {
	t.Helper()
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || got.EventID != id {
		t.Fatalf("unconfirmed event was removed: ok=%v err=%v", ok, err)
	}
}

func retryOf(t *testing.T, err error) *RetryError {
	t.Helper()
	var re *RetryError
	if !errors.As(err, &re) {
		t.Fatalf("expected a retry, got %v", err)
	}
	return re
}

func TestLegacySuccessIsNotDurableReceipt(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"queued"}`))
	}))
	defer s.Close()
	sender, j, id := newSenderFixture(t, s.URL)
	if err := sender.Step(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("legacy success was ACKed")
	}
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || got.EventID != id {
		t.Fatal("unconfirmed event was removed")
	}
}

func TestSenderAcksMatchingReceipt(t *testing.T) {
	var body Envelope
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != SendPath || r.Method != http.MethodPost || r.Header.Get("X-Agent-Token") != "test-token" {
			t.Errorf("unexpected request %s %s token=%q", r.Method, r.URL.Path, r.Header.Get("X-Agent-Token"))
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(receiptFor(body.EventID, "accepted")))
	}))
	defer s.Close()
	sender, j, id := newSenderFixture(t, s.URL)
	if err := sender.Step(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if body.EventID != id || body.ProtocolVersion != 2 || body.Cursor == nil || body.Cursor.Source != "syslog" {
		t.Fatalf("server did not receive the journal envelope: %+v", body)
	}
	if strings.Contains(fmt.Sprint(body), "test-token") {
		t.Fatal("credential leaked into the evidence body")
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || ok {
		t.Fatalf("acknowledged event still queued: ok=%v err=%v", ok, err)
	}
	if j.Snapshot().LastReceiptAt == nil {
		t.Fatal("receipt time not recorded")
	}
	if err := sender.Step(context.Background(), time.Now().UTC()); !errors.Is(err, ErrIdle) {
		t.Fatalf("empty journal should be idle, got %v", err)
	}
}

func TestSenderRejectsReceiptsThatDoNotMatch(t *testing.T) {
	cases := map[string]func(eventID string) string{
		"wrong event": func(string) string { return receiptFor("44444444-4444-4444-8444-444444444444", "accepted") },
		"wrong version": func(id string) string {
			return strings.Replace(receiptFor(id, "accepted"), `"protocol_version":2`, `"protocol_version":1`, 1)
		},
		"queued status": func(id string) string { return receiptFor(id, "queued") },
		"bad receipt": func(id string) string {
			return strings.Replace(receiptFor(id, "accepted"), testReceipt, "not-a-uuid", 1)
		},
		"zero receipt": func(id string) string {
			return strings.Replace(receiptFor(id, "accepted"), testReceipt, "00000000-0000-0000-0000-000000000000", 1)
		},
		"malformed JSON":  func(string) string { return `{"protocol_version":2,` },
		"oversized reply": func(id string) string { return receiptFor(id, "accepted") + strings.Repeat(" ", maxResponseBytes) },
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			var eventID atomic.Value
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(reply(eventID.Load().(string))))
			}))
			defer s.Close()
			sender, j, id := newSenderFixture(t, s.URL)
			eventID.Store(id)
			re := retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
			if re.Reason != "unconfirmed_response" {
				t.Fatalf("reason %q", re.Reason)
			}
			retained(t, j, id)
		})
	}
}

func TestSenderRetriesWhenTheResponseIsLostAfterCommit(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		if calls.Add(1) == 1 { // committed server side, then the connection drops
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(receiptFor(e.EventID, "duplicate")))
	}))
	defer s.Close()
	sender, j, id := newSenderFixture(t, s.URL)
	first := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	re := retryOf(t, sender.Step(context.Background(), first))
	if re.Reason != "network" || re.After < time.Second || re.After > maxBackoff {
		t.Fatalf("network retry %+v", re)
	}
	retained(t, j, id)
	if err := sender.Step(context.Background(), first.Add(time.Minute)); err != nil {
		t.Fatalf("duplicate receipt was not accepted: %v", err)
	}
	if _, ok, _ := j.Peek(context.Background()); ok {
		t.Fatal("event still queued after duplicate receipt")
	}
	if got := j.Snapshot().Retries; got != 1 {
		t.Fatalf("retries=%d, want 1", got)
	}
}

func TestSenderRetryableStatusesKeepEvidence(t *testing.T) {
	cases := []struct {
		status     int
		retryAfter string
		want       time.Duration
	}{
		{http.StatusRequestTimeout, "", time.Second},
		{http.StatusTooManyRequests, "7", 7 * time.Second},
		{http.StatusInternalServerError, "", time.Second},
		{http.StatusBadGateway, "", time.Second},
		{http.StatusServiceUnavailable, "9999", maxRetryAfter},
		{http.StatusServiceUnavailable, "0", minRetryAfter},
		{http.StatusGatewayTimeout, "soon", time.Second},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d-%s", c.status, c.retryAfter), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.retryAfter != "" {
					w.Header().Set("Retry-After", c.retryAfter)
				}
				w.WriteHeader(c.status)
			}))
			defer s.Close()
			sender, j, id := newSenderFixture(t, s.URL)
			re := retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
			if re.After != c.want {
				t.Fatalf("after=%v, want %v", re.After, c.want)
			}
			retained(t, j, id)
		})
	}
}

func TestSenderBackoffGrowsToSixtySecondsAndResets(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(receiptFor(e.EventID, "accepted")))
	}))
	defer s.Close()
	sender, j, _ := newSenderFixture(t, s.URL)
	var delays []time.Duration
	now := time.Now().UTC()
	for i := 0; i < 9; i++ {
		delays = append(delays, retryOf(t, sender.Step(context.Background(), now)).After)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i := range want {
		if delays[i] != want[i]*time.Second {
			t.Fatalf("delays=%v", delays)
		}
	}
	fail.Store(false)
	if err := sender.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	second := journalEvent(t, j.options)
	if err := j.Append(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if got := retryOf(t, sender.Step(context.Background(), now)).After; got != time.Second {
		t.Fatalf("backoff not reset after success: %v", got)
	}
	// jitter stays within [1s, base]
	sender.Jitter = nil
	for i := 0; i < 20; i++ {
		if got := retryOf(t, sender.Step(context.Background(), now)).After; got < time.Second || got > maxBackoff {
			t.Fatalf("jittered delay %v out of bounds", got)
		}
	}
}

func TestSenderAuthAndApprovalRetrySlowlyWithoutQuarantine(t *testing.T) {
	cases := []struct {
		status int
		body   string
		reason string
	}{
		{http.StatusForbidden, `{"detail":"pending_approval"}`, "pending_approval"},
		{http.StatusUnauthorized, `{"detail":"Invalid agent token"}`, "auth_blocked"},
		{http.StatusForbidden, `{"detail":"agent_identity_mismatch"}`, "auth_blocked"},
		{http.StatusForbidden, `not json`, "auth_blocked"},
	}
	for _, c := range cases {
		t.Run(c.reason+c.body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer s.Close()
			sender, j, id := newSenderFixture(t, s.URL)
			re := retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
			if re.Reason != c.reason || re.After != slowRetry {
				t.Fatalf("%+v", re)
			}
			retained(t, j, id)
			if got := sender.Status(); got.State != "blocked" || got.Reason != c.reason {
				t.Fatalf("status %+v", got)
			}
			if j.Snapshot().Quarantined != 0 {
				t.Fatal("auth failure quarantined evidence")
			}
		})
	}
}

func TestSenderQuarantinesPermanentRejectionsAndContinues(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var e Envelope
				_ = json.NewDecoder(r.Body).Decode(&e)
				if calls.Add(1) == 1 {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(receiptFor(e.EventID, "accepted")))
			}))
			defer s.Close()
			sender, j, rejected := newSenderFixture(t, s.URL)
			next := journalEvent(t, j.options)
			if err := j.Append(context.Background(), next); err != nil {
				t.Fatal(err)
			}
			if err := sender.Step(context.Background(), time.Now().UTC()); err != nil {
				t.Fatalf("permanent rejection should quarantine and move on: %v", err)
			}
			retained(t, j, next.EventID) // quarantined record is skipped, not delivered
			if err := sender.Step(context.Background(), time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			h := j.Snapshot()
			if h.Quarantined != 1 || h.QueuedEvents != 1 {
				t.Fatalf("quarantine not retained: %+v", h)
			}
			if err := j.Ack(context.Background(), rejected, testReceipt); !errors.Is(err, ErrTerminal) {
				t.Fatalf("quarantined event can be acked: %v", err)
			}
		})
	}
}

func TestSenderStopsQuarantiningWhenEveryRecordIsRejected(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity) // e.g. a server-side schema regression
	}))
	defer s.Close()
	sender, j, _ := newSenderFixture(t, s.URL)
	for i := 0; i < maxConsecutiveRejects; i++ {
		if err := j.Append(context.Background(), journalEvent(t, j.options)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxConsecutiveRejects; i++ {
		if err := sender.Step(context.Background(), time.Now().UTC()); err != nil {
			t.Fatalf("rejection %d: %v", i, err)
		}
	}
	head, _, _ := j.Peek(context.Background())
	re := retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
	if re.Reason != "repeated_rejections" || re.After != slowRetry {
		t.Fatalf("%+v", re)
	}
	retained(t, j, head.EventID)
	if got := j.Snapshot().Quarantined; got != int64(maxConsecutiveRejects) {
		t.Fatalf("quarantined %d", got)
	}
}

func TestSenderHoldsAfterThirtyDayUncertainty(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer s.Close()
	sender, j, id := newSenderFixture(t, s.URL)
	first := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	retryOf(t, sender.Step(context.Background(), first))
	retryOf(t, sender.Step(context.Background(), first.Add(29*24*time.Hour)))
	if err := sender.Step(context.Background(), first.Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("resent after the uncertainty window: %d requests", calls.Load())
	}
	if h := j.Snapshot(); h.Held != 1 {
		t.Fatalf("not held: %+v", h)
	}
	if _, ok, _ := j.Peek(context.Background()); ok {
		t.Fatal("held event still offered for sending")
	}
	at, ok, err := j.FirstAttempt(context.Background(), id)
	if err != nil || !ok || !at.Equal(first) {
		t.Fatalf("first attempt %v %v %v", at, ok, err)
	}
}

func TestSenderNeverAttemptedEventsDoNotAgeOut(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(receiptFor(e.EventID, "accepted")))
	}))
	defer s.Close()
	sender, _, _ := newSenderFixture(t, s.URL) // collected 2026-10-21, offline since
	if err := sender.Step(context.Background(), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("offline evidence never attempted must still be sent: %v", err)
	}
}

func TestSenderWaitsForProtocolSupport(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer s.Close()
	sender, j, id := newSenderFixture(t, s.URL)
	sender.SupportsV2 = func() bool { return false }
	re := retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
	if re.Reason != "protocol_unsupported" || calls.Load() != 0 {
		t.Fatalf("%+v calls=%d", re, calls.Load())
	}
	retained(t, j, id)
	if _, ok, _ := j.FirstAttempt(context.Background(), id); ok {
		t.Fatal("an attempt was recorded without sending")
	}
}

func TestSenderUnknownStatusesBlockWithoutLosingEvidence(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusTeapot} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}))
			defer s.Close()
			sender, j, id := newSenderFixture(t, s.URL)
			re := retryOf(t, sender.Step(context.Background(), time.Now().UTC()))
			if re.Reason != fmt.Sprintf("unexpected_status_%d", status) || re.After != slowRetry {
				t.Fatalf("%+v", re)
			}
			retained(t, j, id)
			if sender.Status().State != "blocked" {
				t.Fatal("unknown status not visible as blocked")
			}
		})
	}
}

func TestSenderClosesEveryResponseBody(t *testing.T) {
	statuses := []int{http.StatusAccepted, http.StatusInternalServerError, http.StatusForbidden, http.StatusUnprocessableEntity, http.StatusTeapot}
	for _, status := range statuses {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			tracker := &bodyTracker{}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"status":"queued"}`))
			}))
			defer s.Close()
			sender, _, _ := newSenderFixture(t, s.URL)
			sender.Transport = tracker.wrap(client.New(s.URL, "test-token"))
			_ = sender.Step(context.Background(), time.Now().UTC())
			if tracker.open.Load() != 0 || tracker.seen.Load() != 1 {
				t.Fatalf("open bodies=%d seen=%d", tracker.open.Load(), tracker.seen.Load())
			}
		})
	}
}

type bodyTracker struct{ open, seen atomic.Int32 }

type trackedTransport struct {
	inner   Transport
	tracker *bodyTracker
}

type trackedBody struct {
	io.ReadCloser
	tracker *bodyTracker
	closed  atomic.Bool
}

func (b *trackedBody) Close() error {
	if b.closed.CompareAndSwap(false, true) {
		b.tracker.open.Add(-1)
	}
	return b.ReadCloser.Close()
}

func (t *bodyTracker) wrap(inner Transport) Transport { return trackedTransport{inner, t} }

func (t trackedTransport) PostContext(ctx context.Context, path string, payload any) (*http.Response, error) {
	resp, err := t.inner.PostContext(ctx, path, payload)
	if resp != nil {
		t.tracker.open.Add(1)
		t.tracker.seen.Add(1)
		resp.Body = &trackedBody{ReadCloser: resp.Body, tracker: t.tracker}
	}
	return resp, err
}

func TestSenderRunDeliversThenWaitsUntilCanceled(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(receiptFor(e.EventID, "accepted")))
	}))
	defer s.Close()
	sender, j, _ := newSenderFixture(t, s.URL)
	ctx, cancel := context.WithCancel(context.Background())
	var waits []time.Duration
	sender.Wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		cancel()
		return ctx.Err()
	}
	if err := sender.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run returned %v", err)
	}
	if _, ok, _ := j.Peek(context.Background()); ok {
		t.Fatal("run did not deliver the backlog")
	}
	if len(waits) != 1 || waits[0] != idlePoll {
		t.Fatalf("waits %v", waits)
	}
}
