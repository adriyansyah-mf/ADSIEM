package firewall

import "fmt"

type Backend interface {
	Name() string
	Ensure() error
	Apply(rule Rule) error
	Remove(rule Rule) error
	List() ([]Rule, error)
	Flush() error
	Available() bool
}

type plannedOp struct {
	Op    string
	Rule  Rule
	Argv  []string
}

type NoopBackend struct {
	DryRun bool
	ops    []plannedOp
}

func NewNoop(dryRun bool) *NoopBackend {
	return &NoopBackend{DryRun: dryRun}
}

func (n *NoopBackend) Name() string {
	if n.DryRun {
		return "noop(dry-run)"
	}
	return "noop"
}

func (n *NoopBackend) Available() bool { return false }

func (n *NoopBackend) Ensure() error { return nil }

func (n *NoopBackend) Apply(rule Rule) error {
	n.ops = append(n.ops, plannedOp{Op: "apply", Rule: rule, Argv: nftApplyArgv(rule)})
	return nil
}

func (n *NoopBackend) Remove(rule Rule) error {
	n.ops = append(n.ops, plannedOp{Op: "remove", Rule: rule, Argv: nftRemoveArgv(rule)})
	return nil
}

func (n *NoopBackend) List() ([]Rule, error) {
	out := make([]Rule, 0, len(n.ops))
	for _, op := range n.ops {
		if op.Op == "apply" {
			out = append(out, op.Rule)
		}
	}
	return out, nil
}

func (n *NoopBackend) Flush() error {
	n.ops = nil
	return nil
}

func (n *NoopBackend) PlannedCommands() []string {
	out := make([]string, 0, len(n.ops))
	for _, op := range n.ops {
		out = append(out, fmt.Sprintf("nft %v", op.Argv))
	}
	return out
}
