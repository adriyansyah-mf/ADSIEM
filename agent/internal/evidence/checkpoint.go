package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"
)

// Ack persists receipt coverage for every identical local occurrence of eventID.
// Held/quarantined evidence cannot be reclassified as remotely delivered.
func (j *Journal) Ack(ctx context.Context, eventID, receiptID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	if err := ValidateAgentID(receiptID); err != nil {
		return err
	}
	c := j.nextCheckpoint()
	found := false
	changed := false
	var original []byte
	if c.States[eventID].State != "" {
		return ErrTerminal
	}
	err := j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) {
		if e.EventID != eventID {
			return false, nil
		}
		found = true
		encoded, err := json.Marshal(e)
		if err != nil {
			return false, err
		}
		if original == nil {
			original = encoded
		} else if !bytes.Equal(original, encoded) {
			return false, ErrConflict
		}
		if !acknowledged(c, p) {
			addACK(&c, p)
			changed = true
		}
		return false, nil
	})
	if err != nil {
		return j.readFailed(err)
	}
	if !found {
		return ErrUnknownEvent
	}
	if !changed {
		return nil
	}
	delete(c.States, eventID)
	at := j.now().UTC()
	c.Health.LastReceiptAt = &at
	return j.publish(ctx, c)
}

// MarkAttempt preserves the first attempt across retries and process restarts.
// The Sender must compare FirstAttempt to its time and Hold at 30 days.
func (j *Journal) MarkAttempt(ctx context.Context, eventID string, at time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	if at.IsZero() {
		return ErrInvalidControl
	}
	c := j.nextCheckpoint()
	found := false
	if c.States[eventID].State != "" {
		return ErrTerminal
	}
	err := j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) {
		if e.EventID == eventID && !acknowledged(c, p) {
			found = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return j.readFailed(err)
	}
	if !found {
		return ErrUnknownEvent
	}
	s := c.States[eventID]
	if s.FirstAttempt.IsZero() {
		s.FirstAttempt = at.UTC()
	} else {
		if c.Health.Retries == maxCounter {
			return ErrInvalidControl
		}
		c.Health.Retries++
	}
	c.States[eventID] = s
	return j.publish(ctx, c)
}

// FirstAttempt returns the original persisted timestamp for a retained event.
func (j *Journal) FirstAttempt(ctx context.Context, eventID string) (time.Time, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	found := false
	err := j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) { found = e.EventID == eventID; return found, nil })
	if err != nil {
		return time.Time{}, false, j.readFailed(err)
	}
	if !found {
		return time.Time{}, false, ErrUnknownEvent
	}
	at := j.checkpoint.States[eventID].FirstAttempt
	return at, !at.IsZero(), nil
}

func (j *Journal) Hold(ctx context.Context, eventID, reason string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.markTerminal(ctx, eventID, eventState{State: "held", Reason: reason})
}

func (j *Journal) Quarantine(ctx context.Context, eventID, reason string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.markTerminal(ctx, eventID, eventState{State: "quarantined", Reason: reason})
}

func boundedText(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && utf8.ValidString(value)
}

func (j *Journal) markTerminal(ctx context.Context, eventID string, target eventState) error {
	if err := j.ready(ctx); err != nil {
		return err
	}
	if !boundedText(target.Reason, 256) {
		return ErrInvalidControl
	}
	c := j.nextCheckpoint()
	current := c.States[eventID]
	if current.State != "" {
		if current.State == target.State && current.Reason == target.Reason {
			return nil
		}
		return ErrConflict
	}
	found := false
	covered := false
	err := j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) {
		if e.EventID == eventID {
			found = true
			covered = covered || acknowledged(c, p)
		}
		return false, nil
	})
	if err != nil {
		return j.readFailed(err)
	}
	if !found {
		return ErrUnknownEvent
	}
	if covered {
		return ErrConflict
	}
	target.FirstAttempt = current.FirstAttempt
	c.States[eventID] = target
	switch target.State {
	case "held":
		if c.Health.Held == maxCounter {
			return ErrInvalidControl
		}
		c.Health.Held++
	case "quarantined":
		if c.Health.Quarantined == maxCounter {
			return ErrInvalidControl
		}
		c.Health.Quarantined++
	default:
		return ErrInvalidControl
	}
	return j.publish(ctx, c)
}
