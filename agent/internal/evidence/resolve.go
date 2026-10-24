package evidence

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrDuplicateRisk: releasing held evidence may resend an event the server
	// already processed; the operator must accept that explicitly.
	ErrDuplicateRisk = errors.New("evidence: event may already be processed; releasing it can duplicate detections")
	// ErrNotResolvable: only held or quarantined evidence takes operator action.
	ErrNotResolvable = errors.New("evidence: event is not held or quarantined")
)

// maxAudit bounds the operator audit trail kept in the checkpoint. It counts
// against the reserved control budget: at most ~26 KB with 256-byte reasons.
const maxAudit = 64

// AuditEntry records one operator action on parked evidence.
type AuditEntry struct {
	At            time.Time `json:"at"`
	Action        string    `json:"action"` // release | discard
	EventID       string    `json:"event_id"`
	PriorState    string    `json:"prior_state"`
	Reason        string    `json:"reason"`
	DuplicateRisk bool      `json:"duplicate_risk,omitempty"`
}

// RecordInfo describes a retained event without its payload.
type RecordInfo struct {
	EventID      string    `json:"event_id"`
	CollectedAt  time.Time `json:"collected_at"`
	LogType      string    `json:"log_type"`
	Location     string    `json:"location"`
	Bytes        int64     `json:"bytes"`
	State        string    `json:"state"` // held | quarantined
	Reason       string    `json:"reason"`
	FirstAttempt time.Time `json:"first_attempt,omitempty"`
}

// Records lists held and quarantined evidence (metadata only) and counts the
// events still waiting to be delivered.
func (j *Journal) Records(ctx context.Context) ([]RecordInfo, int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var parked []RecordInfo
	pending := 0
	seen := map[string]bool{}
	err := j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) {
		if acknowledged(j.checkpoint, p) || seen[e.EventID] {
			return false, nil
		}
		seen[e.EventID] = true
		s := j.checkpoint.States[e.EventID]
		if s.State == "" {
			pending++
			return false, nil
		}
		parked = append(parked, RecordInfo{EventID: e.EventID, CollectedAt: e.CollectedAt, LogType: e.LogType,
			Location: e.Location, Bytes: p.End - p.Offset, State: s.State, Reason: s.Reason, FirstAttempt: s.FirstAttempt})
		return false, nil
	})
	return parked, pending, j.readFailed(err)
}

// Audit returns the operator actions recorded in the checkpoint, oldest first.
func (j *Journal) Audit() []AuditEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]AuditEntry(nil), j.checkpoint.Audit...)
}

// Resolve applies an operator action to held or quarantined evidence, with
// the agent stopped (the caller owns the journal's exclusive lock):
//
//   - release makes it deliverable again with a new uncertainty window. Held
//     evidence was sent without a receipt for 30 days and may already be
//     processed, so it needs allowDuplicate.
//   - discard drops it: the event is marked delivered so compaction reclaims
//     it. The tombstone and the audit entry are one durable checkpoint, written
//     before any space is reclaimed.
func (j *Journal) Resolve(ctx context.Context, eventID, action, reason string, allowDuplicate bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	if !boundedText(reason, 256) || (action != "release" && action != "discard") {
		return ErrInvalidControl
	}
	c := j.nextCheckpoint()
	var positions []eventPosition
	for _, p := range j.positions(eventID) {
		if !acknowledged(c, p) {
			positions = append(positions, p)
		}
	}
	if len(positions) == 0 {
		return ErrUnknownEvent
	}
	prior := c.States[eventID].State
	if prior != "held" && prior != "quarantined" {
		return ErrNotResolvable
	}
	risk := action == "release" && prior == "held"
	if risk && !allowDuplicate {
		return ErrDuplicateRisk
	}
	if action == "discard" {
		for _, p := range positions {
			addACK(&c, p)
		}
	}
	delete(c.States, eventID)
	c.Audit = append(append([]AuditEntry(nil), c.Audit...), AuditEntry{
		At: j.now().UTC(), Action: action, EventID: eventID, PriorState: prior, Reason: reason, DuplicateRisk: risk,
	})
	if len(c.Audit) > maxAudit {
		c.Audit = c.Audit[len(c.Audit)-maxAudit:]
	}
	if err := j.publish(ctx, c); err != nil {
		return err
	}
	j.resetPeek() // a released record before the last Peek is deliverable again
	return nil
}
