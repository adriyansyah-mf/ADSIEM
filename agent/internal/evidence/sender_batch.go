package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// BatchPath is the durable batch endpoint (server-api POST /api/ingest/v2/logs),
// used only while the heartbeat advertises evidence_batch_max > 1.
const BatchPath = "/api/ingest/v2/logs"

const (
	// One request carries at most this many events and journal bytes; the
	// server refuses bodies over 4 MiB, and one event is at most 1 MiB.
	sendBatchEvents       = 200
	sendBatchBytes        = 2 << 20
	maxBatchResponseBytes = 256 << 10
)

type batchRequest struct {
	ProtocolVersion int        `json:"protocol_version"`
	Events          []Envelope `json:"events"`
}

type batchResult struct {
	EventID   string `json:"event_id"`
	Status    string `json:"status"` // accepted | duplicate | rejected | retry
	ReceiptID string `json:"receipt_id"`
	Code      int    `json:"code"`
}

type batchResponse struct {
	ProtocolVersion int           `json:"protocol_version"`
	Results         []batchResult `json:"results"`
}

// batchLimit is how many events the next batch may carry: the advertised
// maximum, capped, and halved after a request-level validation refusal so a
// single bad event is isolated and quarantined instead of blocking the rest.
func (s *Sender) batchLimit(advertised int) int {
	n := min(advertised, sendBatchEvents)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.split > 0 && s.split < n {
		n = s.split
	}
	return n
}

func (s *Sender) stepBatch(ctx context.Context, now time.Time, advertised int) error {
	peeked, err := s.Journal.PeekBatch(ctx, s.batchLimit(advertised), sendBatchBytes)
	if err != nil {
		return err
	}
	if len(peeked) == 0 {
		s.setStatus("idle", "")
		return ErrIdle
	}
	batch := make([]Envelope, 0, len(peeked))
	ids := make([]string, 0, len(peeked))
	seen := make(map[string]bool, len(peeked))
	for _, e := range peeked {
		if seen[e.EventID] { // an identical re-append: one delivery covers both
			continue
		}
		seen[e.EventID] = true
		first, attempted, err := s.Journal.FirstAttempt(ctx, e.EventID)
		if err != nil {
			return err
		}
		if attempted && now.Sub(first) >= uncertaintyWindow {
			if err := s.Journal.Hold(ctx, e.EventID, "receipt_uncertainty_window"); err != nil {
				return err
			}
			slog.Warn("evidence held: no receipt within the uncertainty window", "event_id", e.EventID, "first_attempt", first)
			continue
		}
		batch, ids = append(batch, e), append(ids, e.EventID)
	}
	if len(batch) == 0 {
		return nil
	}
	// Persist the attempts before any network I/O: the 30-day window starts here.
	if err := s.Journal.MarkAttempts(ctx, ids, now); err != nil {
		if errors.Is(err, ErrFull) && len(ids) > 1 {
			// One attempt record per event: a small control reserve cannot hold
			// a whole batch of them. Narrow the batch instead of retrying it forever.
			s.mu.Lock()
			s.split = max(len(ids)/2, 1)
			s.mu.Unlock()
			return nil
		}
		return err
	}
	return s.deliverBatch(ctx, batch)
}

func (s *Sender) deliverBatch(ctx context.Context, batch []Envelope) error {
	s.setStatus("sending", "")
	timeout := s.AttemptTimeout
	if timeout <= 0 {
		timeout = defaultAttemptTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := s.Transport.PostContext(attemptCtx, BatchPath, batchRequest{ProtocolVersion: 2, Events: batch})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.retry("network", 0, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBatchResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.retry("network", 0, err)
	}

	code := resp.StatusCode
	switch {
	case code == http.StatusOK:
		results, err := matchingResults(body, batch)
		if err != nil {
			return s.retry("unconfirmed_response", 0, err)
		}
		return s.applyResults(ctx, batch, results)
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500 && code <= 599:
		return s.retry(fmt.Sprintf("status_%d", code), retryAfter(resp.Header.Get("Retry-After")), nil)
	case code == http.StatusForbidden && detail(body) == "pending_approval":
		return s.block("pending_approval", slowRetry, nil)
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return s.block("auth_blocked", slowRetry, nil)
	case code == http.StatusBadRequest || code == http.StatusRequestEntityTooLarge || code == http.StatusUnprocessableEntity:
		if len(batch) > 1 {
			// The request as a whole was refused: narrow down to the culprit.
			s.mu.Lock()
			s.split = max(len(batch)/2, 1)
			s.mu.Unlock()
			slog.Warn("evidence batch refused, splitting", "status", code, "events", len(batch))
			return nil
		}
		return s.reject(ctx, batch[0], code)
	default:
		return s.block(fmt.Sprintf("unexpected_status_%d", code), slowRetry, nil)
	}
}

// matchingResults accepts a response only when it answers every sent event,
// in order, with a known status, and every receipt is a valid UUID. Anything
// else acknowledges nothing.
func matchingResults(body []byte, batch []Envelope) ([]batchResult, error) {
	if len(body) > maxBatchResponseBytes {
		return nil, errors.New("batch response too large")
	}
	var r batchResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("batch response: %w", err)
	}
	if r.ProtocolVersion != 2 {
		return nil, fmt.Errorf("batch protocol %d", r.ProtocolVersion)
	}
	if len(r.Results) != len(batch) {
		return nil, fmt.Errorf("batch response has %d results for %d events", len(r.Results), len(batch))
	}
	for i, x := range r.Results {
		if x.EventID != batch[i].EventID {
			return nil, errors.New("batch result for another event")
		}
		switch x.Status {
		case "accepted", "duplicate":
			if err := ValidateAgentID(x.ReceiptID); err != nil {
				return nil, fmt.Errorf("receipt id: %w", err)
			}
		case "rejected":
			if x.Code != http.StatusBadRequest && x.Code != http.StatusConflict &&
				x.Code != http.StatusRequestEntityTooLarge && x.Code != http.StatusUnprocessableEntity {
				return nil, fmt.Errorf("rejected with code %d", x.Code)
			}
		case "retry":
		default:
			return nil, fmt.Errorf("batch result status %q", x.Status)
		}
	}
	return r.Results, nil
}

// applyResults acknowledges every receipt in one checkpoint publication, then
// quarantines rejected events; retried events stay queued.
func (s *Sender) applyResults(ctx context.Context, batch []Envelope, results []batchResult) error {
	var receipts []Receipt
	retry := false
	for _, x := range results {
		switch x.Status {
		case "accepted", "duplicate":
			receipts = append(receipts, Receipt{EventID: x.EventID, ReceiptID: x.ReceiptID})
		case "retry":
			retry = true
		}
	}
	if len(receipts) > 0 {
		if err := s.Journal.AckBatch(ctx, receipts); err != nil {
			return err
		}
		s.deliveredN(len(receipts))
	}
	for i, x := range results {
		if x.Status != "rejected" {
			continue
		}
		if err := s.reject(ctx, batch[i], x.Code); err != nil {
			return err
		}
	}
	if retry {
		return s.retry("status_429", 0, nil)
	}
	return nil
}
