package evidence

import (
	"errors"
	"fmt"
)

var ErrInvalidOptions = errors.New("evidence: invalid storage options")

// Options budgets include reserved control bytes in MaxBytes.
type Options struct {
	Dir, AgentID                          string
	MaxBytes, SegmentBytes, ReservedBytes int64
	MaxEventBytes                         int
}

// Validate checks storage budgets independently of enrollment state.
// A journal opener must require a nonempty AgentID before accepting records.
func (o Options) Validate() error {
	if o.AgentID != "" {
		if err := ValidateAgentID(o.AgentID); err != nil {
			return err
		}
	}
	if o.Dir == "" || o.MaxBytes <= 0 || o.SegmentBytes <= 0 || o.ReservedBytes < 0 || o.ReservedBytes >= o.MaxBytes || o.MaxEventBytes <= 0 {
		return fmt.Errorf("positive directory and sizes required: %w", ErrInvalidOptions)
	}
	if o.SegmentBytes > o.MaxBytes-o.ReservedBytes || int64(o.MaxEventBytes) > o.SegmentBytes {
		return fmt.Errorf("segment/event exceed data budget: %w", ErrInvalidOptions)
	}
	return nil
}
