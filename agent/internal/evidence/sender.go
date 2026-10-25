package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// SendPath is the durable ingest endpoint (server-api POST /api/ingest/v2/log).
const SendPath = "/api/ingest/v2/log"

const (
	maxResponseBytes      = 16 << 10
	uncertaintyWindow     = 30 * 24 * time.Hour // from the persisted first attempt
	maxBackoff            = 60 * time.Second
	slowRetry             = 60 * time.Second // auth, approval, blocked
	minRetryAfter         = time.Second
	maxRetryAfter         = 300 * time.Second
	unsupportedRetry      = time.Second // an in-memory check until a heartbeat advertises protocol 2
	idlePoll              = time.Second
	journalRetry          = 5 * time.Second
	defaultAttemptTimeout = 30 * time.Second
	// A server-side validation regression rejects every record: after this many
	// rejections in a row stop quarantining and block, so the backlog stays
	// deliverable once the server is fixed.
	maxConsecutiveRejects = 5
)

// ErrIdle means every retained event is acknowledged, held or quarantined.
var ErrIdle = errors.New("evidence: nothing to send")

// RetryError keeps the event and says when to try again and why.
type RetryError struct {
	Reason string
	After  time.Duration
	Err    error
}

func (e *RetryError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("evidence: retry in %s (%s): %v", e.After, e.Reason, e.Err)
	}
	return fmt.Sprintf("evidence: retry in %s (%s)", e.After, e.Reason)
}

func (e *RetryError) Unwrap() error { return e.Err }

// Transport is the agent HTTP client: it attaches the agent token at send
// time, so credentials never enter a journal record.
type Transport interface {
	PostContext(ctx context.Context, path string, payload any) (*http.Response, error)
}

// SenderStatus is what the sender is doing, for operator visibility.
type SenderStatus struct {
	State    string    `json:"state"` // idle | sending | retrying | blocked
	Reason   string    `json:"reason,omitempty"`
	Since    time.Time `json:"since"`
	Failures int       `json:"failures"`
}

// Sender delivers the journal in order and reclaims an event only for a
// matching durable receipt: HTTP 202, protocol 2, the same event ID, status
// accepted or duplicate, and a valid receipt UUID. Anything else keeps it.
type Sender struct {
	Journal    *Journal
	Transport  Transport
	SupportsV2 func() bool // true once the server advertised protocol 2
	// BatchMax, when set and above 1, is the advertised evidence_batch_max:
	// events then go out in batches to BatchPath instead of one per request.
	BatchMax func() int

	// Optional; defaults suit production. Tests inject them.
	Now            func() time.Time
	Wait           func(context.Context, time.Duration) error
	Jitter         func(time.Duration) time.Duration // backoff base -> delay
	AttemptTimeout time.Duration
	// CompactEvery bounds how often delivered segments are reclaimed
	// (Journal.Compact scans the journal). Default one minute.
	CompactEvery time.Duration

	mu       sync.Mutex
	failures int // consecutive transient failures, for backoff
	rejects  int // consecutive permanent rejections
	split    int // >0: batch size narrowed after a request-level refusal
	status   SenderStatus

	acked       int // acknowledgements since the last compaction
	compactedAt time.Time
}

const defaultCompactEvery = time.Minute

// maybeCompact reclaims fully delivered segments, at most every CompactEvery
// and only after something was acknowledged; without it the journal would
// fill with delivered evidence and refuse new events.
func (s *Sender) maybeCompact(ctx context.Context) {
	every := s.CompactEvery
	if every <= 0 {
		every = defaultCompactEvery
	}
	s.mu.Lock()
	due := s.acked > 0 && time.Since(s.compactedAt) >= every
	s.mu.Unlock()
	if !due {
		return
	}
	if err := s.Journal.Compact(ctx); err != nil {
		if ctx.Err() == nil {
			slog.Warn("evidence journal compaction failed", "err", err)
		}
		return
	}
	s.mu.Lock()
	s.acked, s.compactedAt = 0, time.Now()
	s.mu.Unlock()
}

type receipt struct {
	ProtocolVersion int    `json:"protocol_version"`
	EventID         string `json:"event_id"`
	Status          string `json:"status"`
	ReceiptID       string `json:"receipt_id"`
}

// Step makes one delivery attempt for the oldest unsent event. It returns nil
// when that event was acknowledged, quarantined or held, ErrIdle when there is
// nothing to send, a *RetryError when the event stays queued, and any other
// error for journal failures.
func (s *Sender) Step(ctx context.Context, now time.Time) error {
	if s.SupportsV2 == nil || !s.SupportsV2() {
		return s.block("protocol_unsupported", unsupportedRetry, nil)
	}
	if s.BatchMax != nil {
		if n := s.BatchMax(); n > 1 {
			return s.stepBatch(ctx, now, n)
		}
	}
	e, ok, err := s.Journal.Peek(ctx)
	if err != nil {
		return err
	}
	if !ok {
		s.setStatus("idle", "")
		return ErrIdle
	}
	first, attempted, err := s.Journal.FirstAttempt(ctx, e.EventID)
	if err != nil {
		return err
	}
	if attempted && now.Sub(first) >= uncertaintyWindow {
		// Past the server's receipt retention a resend could be processed twice:
		// leave it to an operator instead of blindly resending.
		if err := s.Journal.Hold(ctx, e.EventID, "receipt_uncertainty_window"); err != nil {
			return err
		}
		slog.Warn("evidence held: no receipt within the uncertainty window", "event_id", e.EventID, "first_attempt", first)
		return nil
	}
	// Persist the attempt before any network I/O: the 30-day window starts here.
	if err := s.Journal.MarkAttempt(ctx, e.EventID, now); err != nil {
		return err
	}
	return s.deliver(ctx, e)
}

func (s *Sender) deliver(ctx context.Context, e Envelope) error {
	s.setStatus("sending", "")
	timeout := s.AttemptTimeout
	if timeout <= 0 {
		timeout = defaultAttemptTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := s.Transport.PostContext(attemptCtx, SendPath, e)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err() // shutting down: not a delivery failure
		}
		return s.retry("network", 0, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.retry("network", 0, err)
	}

	code := resp.StatusCode
	switch {
	case code == http.StatusAccepted:
		receiptID, err := matchingReceipt(body, e.EventID)
		if err != nil {
			return s.retry("unconfirmed_response", 0, err)
		}
		if err := s.Journal.Ack(ctx, e.EventID, receiptID); err != nil {
			return err
		}
		s.delivered()
		return nil
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500 && code <= 599:
		return s.retry(fmt.Sprintf("status_%d", code), retryAfter(resp.Header.Get("Retry-After")), nil)
	case code == http.StatusForbidden && detail(body) == "pending_approval":
		return s.block("pending_approval", slowRetry, nil)
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		// No reenrollment or state deletion: an operator fixes the identity.
		return s.block("auth_blocked", slowRetry, nil)
	case code == http.StatusBadRequest || code == http.StatusConflict ||
		code == http.StatusRequestEntityTooLarge || code == http.StatusUnprocessableEntity:
		return s.reject(ctx, e, code)
	default:
		return s.block(fmt.Sprintf("unexpected_status_%d", code), slowRetry, nil)
	}
}

func matchingReceipt(body []byte, eventID string) (string, error) {
	if len(body) > maxResponseBytes {
		return "", errors.New("receipt response too large")
	}
	var r receipt
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("receipt: %w", err)
	}
	switch {
	case r.ProtocolVersion != 2:
		return "", fmt.Errorf("receipt protocol %d", r.ProtocolVersion)
	case r.EventID != eventID:
		return "", errors.New("receipt for another event")
	case r.Status != "accepted" && r.Status != "duplicate":
		return "", fmt.Errorf("receipt status %q", r.Status)
	}
	if err := ValidateAgentID(r.ReceiptID); err != nil { // the same UUID rules
		return "", fmt.Errorf("receipt id: %w", err)
	}
	return r.ReceiptID, nil
}

func detail(body []byte) string {
	var r struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(body, &r) != nil {
		return ""
	}
	d, _ := r.Detail.(string)
	return d
}

// retryAfter reads a bounded Retry-After in seconds; 0 means use backoff.
func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	d := time.Duration(n) * time.Second
	if d < minRetryAfter {
		return minRetryAfter
	}
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

func (s *Sender) reject(ctx context.Context, e Envelope, code int) error {
	s.mu.Lock()
	rejects := s.rejects
	s.mu.Unlock()
	if rejects >= maxConsecutiveRejects {
		return s.block("repeated_rejections", slowRetry, fmt.Errorf("status %d", code))
	}
	if err := s.Journal.Quarantine(ctx, e.EventID, fmt.Sprintf("rejected_status_%d", code)); err != nil {
		return err
	}
	s.mu.Lock()
	s.rejects++
	s.widen()
	s.mu.Unlock()
	// The raw event is not logged: it may contain sensitive data.
	slog.Warn("evidence quarantined: rejected by the server", "event_id", e.EventID, "status", code)
	return nil
}

func (s *Sender) retry(reason string, after time.Duration, err error) error {
	s.mu.Lock()
	s.failures++
	if after <= 0 {
		base := maxBackoff
		if s.failures <= 6 { // 1, 2, 4 ... 32 seconds, then 60
			base = time.Second << (s.failures - 1)
		}
		after = s.jitter(base)
	}
	s.mu.Unlock()
	s.setStatus("retrying", reason)
	return &RetryError{Reason: reason, After: after, Err: err}
}

func (s *Sender) jitter(base time.Duration) time.Duration {
	d := base
	if s.Jitter != nil {
		d = s.Jitter(base)
	} else {
		d = base/2 + time.Duration(rand.Int64N(int64(base/2)+1))
	}
	if d < time.Second {
		d = time.Second
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func (s *Sender) block(reason string, after time.Duration, err error) error {
	s.setStatus("blocked", reason)
	return &RetryError{Reason: reason, After: after, Err: err}
}

func (s *Sender) delivered() { s.deliveredN(1) }

func (s *Sender) deliveredN(n int) {
	s.mu.Lock()
	s.failures, s.rejects = 0, 0
	s.acked += n
	s.widen()
	s.mu.Unlock()
	s.setStatus("sending", "")
}

// widen grows a narrowed batch size back after progress. Caller holds s.mu.
func (s *Sender) widen() {
	if s.split > 0 {
		if s.split *= 2; s.split >= sendBatchEvents {
			s.split = 0
		}
	}
}

func (s *Sender) setStatus(state, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State != state || s.status.Reason != reason {
		if state == "blocked" && s.status.Reason != reason {
			slog.Warn("evidence sending blocked", "reason", reason)
		}
		s.status = SenderStatus{State: state, Reason: reason, Since: s.now()}
	}
	s.status.Failures = s.failures
}

// Status returns a copy of the current sender state.
func (s *Sender) Status() SenderStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Sender) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Sender) wait(ctx context.Context, d time.Duration) error {
	if s.Wait != nil {
		return s.Wait(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run delivers until ctx is canceled. Journal failures are logged and retried;
// they never fall back to another delivery path.
func (s *Sender) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := s.Step(ctx, s.now())
		s.maybeCompact(ctx)
		var delay time.Duration
		var re *RetryError
		switch {
		case err == nil:
			continue
		case errors.Is(err, ErrIdle):
			delay = idlePoll
		case errors.As(err, &re):
			delay = re.After
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			slog.Error("evidence sender: journal error", "err", err)
			delay = journalRetry
		}
		if err := s.wait(ctx, delay); err != nil {
			return err
		}
	}
}
