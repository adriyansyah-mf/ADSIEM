package firewall

import "fmt"

// BlockFromDetection applies a locally-detected block through the same guard
// as a server-driven one. A detection that targets a protected address is
// refused rather than silently swallowed, so the caller can record why.
func (e *Engine) BlockFromDetection(ruleKey, cidr string, ttlSeconds int) error {
	rule := Rule{
		Action:    ActionBlock,
		CIDR:      cidr,
		Direction: DirBoth,
		Reason:    fmt.Sprintf("local:%s", ruleKey),
	}
	if ttlSeconds > 0 {
		rule.TTL = secondsToDuration(ttlSeconds)
	}
	if _, err := e.Add(rule); err != nil {
		return err
	}
	return nil
}

// BlockedEntries reports how many rules the engine currently tracks, which the
// detection engine uses to enforce its entry cap.
func (e *Engine) BlockedEntries() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.applied)
}
