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

func (r *Runner) handleBlockIP(params map[string]any) (any, error) {
	eng, err := r.firewallEngine()
	if err != nil {
		return nil, err
	}

	rule, err := firewall.ParseRule(params)
	if err != nil {
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

func (r *Runner) handleIsolateHost() (any, error) {
	eng, err := r.firewallEngine()
	if err != nil {
		return nil, err
	}
	return eng.Isolate()
}

func (r *Runner) handleUnisolateHost() (any, error) {
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
