//go:build linux

package prevent

import (
	"log/slog"
	"sync"
)

// linuxEngines runs the BPF LSM engine when the kernel has it and starts
// the fanotify engine only while a policy needs it: hash rules, or any
// rules on a kernel without BPF LSM.
type linuxEngines struct {
	report func(Decision)
	lsm    *lsmEngine

	mu  sync.Mutex
	fan *fanClient
}

// noLSM makes the tests run the fanotify-only path on a BPF LSM kernel.
var noLSM = false

func startEngines(report func(Decision)) (engines, error) {
	e := &linuxEngines{report: report}
	if noLSM {
		return e, nil
	}
	lsm, err := startLSM(report)
	if err != nil {
		slog.Info("prevent: BPF LSM engine unavailable, fanotify decides every rule", "reason", err)
	}
	e.lsm = lsm
	return e, nil
}

func (e *linuxEngines) apply(p *Policy) {
	if e.lsm != nil {
		if err := e.lsm.apply(p); err != nil {
			slog.Warn("prevent: could not load rules into the BPF LSM engine", "err", err)
		}
	}
	needFan := len(p.Rules) > 0 && (e.lsm == nil || p.HasHashRules())
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case needFan && e.fan == nil:
		fan, err := startFanotify(e.report)
		if err != nil {
			slog.Warn("prevent: fanotify engine unavailable; these rules are not enforced", "err", err,
				"hash_rules", p.HasHashRules(), "lsm", e.lsm != nil)
			return
		}
		e.fan = fan
	case !needFan && e.fan != nil:
		e.fan.close()
		e.fan = nil
		return
	}
	if e.fan != nil {
		e.fan.setPolicy(p, e.lsm != nil)
	}
}

func (e *linuxEngines) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fan != nil {
		e.fan.close()
	}
	if e.lsm != nil {
		e.lsm.close()
	}
}
