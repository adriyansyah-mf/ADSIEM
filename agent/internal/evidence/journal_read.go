package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
)

func (j *Journal) checkDuplicate(ctx context.Context, e Envelope) error {
	if err := j.ready(ctx); err != nil {
		return err
	}
	if _, exists := j.checkpoint.States[e.EventID]; exists {
		return ErrConflict
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		return err
	}
	err = j.walkEvents(ctx, func(existing Envelope, p eventPosition) (bool, error) {
		if existing.EventID != e.EventID {
			return false, nil
		}
		if acknowledged(j.checkpoint, p) {
			return false, ErrConflict
		}
		previous, err := json.Marshal(existing)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(previous, encoded) {
			return false, ErrConflict
		}
		return false, nil
	})
	return j.readFailed(err)
}

func (j *Journal) Peek(ctx context.Context) (Envelope, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return Envelope{}, false, os.ErrClosed
	}
	var next Envelope
	found := false
	err := j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) {
		if acknowledged(j.checkpoint, p) || j.checkpoint.States[e.EventID].State != "" {
			return false, nil
		}
		next = e
		found = true
		return true, nil
	})
	return next, found, j.readFailed(err)
}
