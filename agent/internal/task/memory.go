// agent/internal/task/memory.go
package task

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/siem-platform/agent/internal/memscan"
)

// Process memory: YARA over a process's regions, and writable+executable
// private memory. pid 0 means every process.

func memTargets(pid int) ([]memscan.Proc, error) {
	if pid > 0 {
		return []memscan.Proc{{PID: pid, Image: memscan.ProcessImage(pid)}}, nil
	}
	procs, err := memscan.Processes()
	if err != nil {
		return nil, err
	}
	self := os.Getpid()
	out := procs[:0]
	for _, p := range procs {
		if p.PID != self { // the agent holds the rules themselves in memory
			out = append(out, p)
		}
	}
	return out, nil
}

func hexAddr(a uint64) string { return "0x" + strconv.FormatUint(a, 16) }

func pluginMemYara(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	rulesRaw, _ := args["rules"].([]any)
	rules, ruleErrs := compileYaraRules(rulesRaw)
	for _, e := range ruleErrs {
		if err := emit(map[string]any{"Rule": e.Rule, "Error": e.Error}); err != nil {
			return err
		}
	}
	if rules.Len() == 0 {
		return fmt.Errorf("no YARA rules supplied")
	}
	procs, err := memTargets(argInt(args, "pid", 0))
	if err != nil {
		return err
	}
	lim := memscan.Limits{AnonOnly: argBool(args, "anon_only", false)}
	for _, p := range procs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		res, err := memscan.Scan(ctx, rules, p.PID, lim)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue // exited, or not readable (protected process)
		}
		for _, m := range res.Matches {
			if err := emit(map[string]any{
				"Pid": p.PID, "Process": res.Image, "Rule": m.Rule, "Namespace": m.Namespace,
				"Address": hexAddr(m.Address), "RegionStart": hexAddr(m.Region.Start), "RegionPerms": m.Region.Perms,
				"RegionKind": m.Region.Kind, "RegionPath": m.Region.Path, "Strings": m.Strings,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func pluginMemRWX(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	procs, err := memTargets(argInt(args, "pid", 0))
	if err != nil {
		return err
	}
	for _, p := range procs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		regions, err := memscan.SuspiciousRegions(p.PID)
		if err != nil {
			continue
		}
		for _, r := range regions {
			if err := emit(map[string]any{
				"Pid": p.PID, "Process": p.Image, "Start": hexAddr(r.Start), "End": hexAddr(r.End),
				"Size": r.Size(), "Perms": r.Perms, "Kind": r.Kind, "Path": r.Path,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// MemoryScanResult is the memory_scan task's result.
type MemoryScanResult struct {
	ProcessesScanned int              `json:"processes_scanned"`
	ProcessesSkipped int              `json:"processes_skipped"`
	BytesScanned     int64            `json:"bytes_scanned"`
	Matches          []map[string]any `json:"matches"`
	RuleErrors       []YaraRuleError  `json:"rule_errors,omitempty"`
	Warnings         []string         `json:"warnings,omitempty"`
}

func runMemoryScan(pid int, rulesRaw []any) (MemoryScanResult, error) {
	rules, ruleErrs := compileYaraRules(rulesRaw)
	res := MemoryScanResult{RuleErrors: ruleErrs, Matches: []map[string]any{}}
	if rules.Len() == 0 {
		return res, fmt.Errorf("no YARA rule compiled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), yaraTaskTimeout)
	defer cancel()
	procs, err := memTargets(pid)
	if err != nil {
		return res, err
	}
	for _, p := range procs {
		if ctx.Err() != nil {
			res.Warnings = append(res.Warnings, "scan timed out; remaining processes skipped")
			break
		}
		r, err := memscan.Scan(ctx, rules, p.PID, memscan.Limits{})
		if err != nil {
			res.ProcessesSkipped++
			continue
		}
		res.ProcessesScanned++
		res.BytesScanned += r.Bytes
		res.Warnings = append(res.Warnings, r.Warnings...)
		for _, m := range r.Matches {
			res.Matches = append(res.Matches, map[string]any{
				"pid": p.PID, "process": r.Image, "rule_name": m.Rule, "namespace": m.Namespace,
				"address": hexAddr(m.Address), "region": hexAddr(m.Region.Start) + " " + m.Region.Perms + " " + m.Region.Kind,
				"region_path": m.Region.Path, "matched_strings": m.Strings,
			})
		}
	}
	return res, nil
}
