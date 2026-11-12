package task

import (
	"fmt"

	"github.com/siem-platform/agent/internal/firewall"
)

func (r *Runner) firewallEngine() (*firewall.Engine, error) {
	if r.fw == nil {
		return nil, fmt.Errorf("firewall gate not initialised")
	}
	return r.fw, nil
}

// requireEnforcing fails a block or isolation the engine would only pretend
// to apply: on the no-op backend (firewall disabled in the agent config, or nft
// unavailable) Add succeeds and nothing is enforced, so the task, the console
// and SOAR all reported a block that never happened. Dry-run is the
// operator's explicit choice and still succeeds (the result says dry_run).
func requireEnforcing(eng *firewall.Engine) error {
	if eng.Enforcing() {
		return nil
	}
	st := eng.Status()
	if dry, _ := st["dry_run"].(bool); dry {
		return nil
	}
	reason, _ := st["degraded"].(string)
	if reason == "" {
		reason = "no enforcing backend"
	}
	return fmt.Errorf("firewall not enforcing on this agent (%s): set firewall.enabled: true in the agent config and restart it", reason)
}

// useNativeBlock: on Windows, block_ip goes through the firewall engine (its
// anti-lockout guard, persistence and expiry) when the engine enforces rules
// (firewall.enabled), and through netsh directly otherwise, as before.
func (r *Runner) useNativeBlock() bool {
	return nativeFirewall && (r.fw == nil || !r.fw.Enforcing())
}

func (r *Runner) handleBlockIP(params map[string]any) (any, error) {
	if r.useNativeBlock() {
		rule, err := firewall.ParseRule(params)
		if err != nil {
			return nil, err
		}
		if err := nativeBlock(rule); err != nil {
			return nil, err
		}
		return map[string]any{"cidr": rule.CIDR, "action": "block", "ttl": rule.TTLSeconds(), "backend": "netsh"}, nil
	}
	eng, err := r.firewallEngine()
	if err != nil {
		return nil, err
	}

	rule, err := firewall.ParseRule(params)
	if err != nil {
		return nil, err
	}
	if err := requireEnforcing(eng); err != nil {
		return nil, err
	}

	applied, err := eng.Add(rule)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"rule_id":   applied.ID,
		"cidr":      applied.CIDR,
		"action":    applied.Action,
		"direction": applied.Direction,
		"ttl":       applied.TTLSeconds(),
		"backend":   eng.Status()["backend"],
		"dry_run":   eng.Status()["dry_run"],
	}, nil
}

func (r *Runner) handleUnblockIP(params map[string]any) (any, error) {
	if r.useNativeBlock() {
		rule, err := firewall.ParseRule(params)
		if err != nil {
			return nil, fmt.Errorf("a valid ip is required: %w", err)
		}
		if err := nativeUnblock(rule); err != nil {
			return nil, err
		}
		return map[string]any{"removed": rule.CIDR}, nil
	}
	eng, err := r.firewallEngine()
	if err != nil {
		return nil, err
	}

	id, _ := params["rule_id"].(string)
	if id == "" {
		rule, perr := firewall.ParseRule(params)
		if perr != nil {
			return nil, fmt.Errorf("rule_id or a valid ip is required: %w", perr)
		}
		id = rule.ID
	}

	if err := eng.Remove(id); err != nil {
		return nil, err
	}
	return map[string]any{"removed": id}, nil
}

// IsolateHost isolates the host for a task or for anti-ransomware. The
// firewall engine does it when it enforces rules (both directions, IPv4 and
// IPv6, the server re-resolved, released when the server stays unreachable);
// on Windows without an enforcing engine, netsh directly as before.
// Elsewhere, a firewall that blocks nothing is an error, never a fake success.
func IsolateHost(eng *firewall.Engine, serverURL string) error {
	_, err := isolateWith(eng, serverURL)
	return err
}

func isolateWith(eng *firewall.Engine, serverURL string) (map[string]any, error) {
	if nativeFirewall && (eng == nil || !eng.Enforcing()) {
		if err := nativeIsolate(serverURL); err != nil {
			return nil, err
		}
		return map[string]any{"isolated": true, "backend": "netsh", "direction": firewall.DirBoth}, nil
	}
	if eng == nil {
		return nil, fmt.Errorf("firewall gate not initialised")
	}
	if err := requireEnforcing(eng); err != nil {
		return nil, err
	}
	return eng.Isolate()
}

func (r *Runner) handleIsolateHost() (any, error) {
	return isolateWith(r.fw, r.cfg.Server.URL)
}

func (r *Runner) handleUnisolateHost() (any, error) {
	if nativeFirewall && (r.fw == nil || !r.fw.Isolated()) {
		// isolated by netsh directly (or by an older agent): same rule names
		if err := nativeUnisolate(); err != nil {
			return nil, err
		}
		return map[string]any{"isolated": false}, nil
	}
	eng, err := r.firewallEngine()
	if err != nil {
		return nil, err
	}
	if err := eng.Unisolate(); err != nil {
		return nil, err
	}
	return map[string]any{"isolated": false}, nil
}

func (r *Runner) handleFirewallList() (any, error) {
	eng, err := r.firewallEngine()
	if err != nil {
		return nil, err
	}
	rules := eng.List()
	return map[string]any{
		"count":     len(rules),
		"rules":     rules,
		"status":    eng.Status(),
		"protected": eng.Status()["protected"],
	}, nil
}

func (r *Runner) handleFirewallFlush() (any, error) {
	eng, err := r.firewallEngine()
	if err != nil {
		return nil, err
	}
	if err := eng.Flush(); err != nil {
		return nil, err
	}
	return map[string]any{"flushed": true}, nil
}
