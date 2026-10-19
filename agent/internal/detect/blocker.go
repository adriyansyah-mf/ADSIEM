package detect

import (
	"errors"
	"time"

	"github.com/siem-platform/agent/internal/firewall"
)

// FirewallBlocker adapts the firewall engine to the detection engine. Both the
// server-driven and locally-detected paths go through the same anti-lockout
// guard, so a local rule cannot block the SIEM server any more than a remote
// task could.
type FirewallBlocker struct {
	engine *firewall.Engine
}

func NewFirewallBlocker(engine *firewall.Engine) *FirewallBlocker {
	return &FirewallBlocker{engine: engine}
}

func (b *FirewallBlocker) Add(ruleKey, ip string, ttl time.Duration) error {
	if b.engine == nil {
		return errNoEngine
	}
	return b.engine.BlockFromDetection(ruleKey, ip, int(ttl/time.Second))
}

func (b *FirewallBlocker) BlockedCount() int {
	if b.engine == nil {
		return 0
	}
	return b.engine.BlockedEntries()
}

var errNoEngine = errors.New("firewall engine not initialised")
