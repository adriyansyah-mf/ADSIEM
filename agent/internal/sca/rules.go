package sca

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// commandTimeout bounds every c: rule the same way the original hardcoded
// firewall/systemctl checks did (firewallCheckTimeout/systemctlCheckTimeout)
// — a hung command (xtables lock contention, a wedged systemctl) must never
// freeze the synchronous hygiene collector that calls into this package.
const commandTimeout = 5 * time.Second

// evalStatus is a rule's own tri-state result, before a PolicyCheck's
// Condition folds several of these into one Status. "skip" means the rule's
// subject doesn't exist on this host (missing file, absent command, no such
// mount) — distinct from "fail", and excluded from condition folding so an
// all-skipped check reports not_applicable rather than a false pass/fail.
type evalStatus int

const (
	evalFail evalStatus = iota
	evalPass
	evalSkip
)

type ruleEval struct {
	status evalStatus
	detail string
}

// rule is one parsed DSL line. Selector identifies the subject (f/c/m/sshd),
// matchType identifies how it's tested (existence/regex/numeric/perm/opts).
type rule struct {
	raw       string
	selector  string // "f" | "c" | "m" | "sshd"
	negate    bool   // "not f:<path>" — bare existence, inverted
	target    string // path | command line | mountpoint | sshd directive name
	matchType string // "exists" | "regex" | "notregex" | "numeric" | "perm" | "opts"
	regex     *regexp.Regexp
	compareOp string
	compareLo float64
	compareHi float64
	permMax   os.FileMode
	opts      []string
	def       string // sshd: fallback value when the directive isn't set
}

// parseRule parses one DSL line. See package doc in engine.go for the full
// grammar with examples; this function is the grammar's only definition.
func parseRule(raw string) (*rule, error) {
	line := strings.TrimSpace(raw)
	r := &rule{raw: raw}

	if strings.HasPrefix(line, "not ") {
		r.negate = true
		line = strings.TrimSpace(strings.TrimPrefix(line, "not "))
	}

	selectorPart := line
	matcherPart := ""
	if idx := strings.Index(line, "->"); idx != -1 {
		selectorPart = strings.TrimSpace(line[:idx])
		matcherPart = strings.TrimSpace(line[idx+2:])
	}

	colon := strings.Index(selectorPart, ":")
	if colon == -1 {
		return nil, errf("rule %q: missing selector prefix (f:/c:/m:/sshd:)", raw)
	}
	r.selector = selectorPart[:colon]
	r.target = selectorPart[colon+1:]

	switch r.selector {
	case "f", "c", "m", "sshd":
	default:
		return nil, errf("rule %q: unknown selector %q", raw, r.selector)
	}

	if matcherPart == "" {
		r.matchType = "exists"
		return r, nil
	}

	// Pull a trailing "default:<value>" off sshd rules before parsing the
	// rest — it's a suffix modifier, not part of the regex/compare grammar.
	if r.selector == "sshd" {
		if idx := strings.LastIndex(matcherPart, " default:"); idx != -1 {
			r.def = strings.TrimSpace(matcherPart[idx+len(" default:"):])
			matcherPart = strings.TrimSpace(matcherPart[:idx])
		}
	}

	switch {
	case strings.HasPrefix(matcherPart, "!r:"):
		pattern := strings.TrimSpace(strings.TrimPrefix(matcherPart, "!r:"))
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errf("rule %q: bad regex: %v", raw, err)
		}
		r.matchType, r.regex = "notregex", re

	case strings.HasPrefix(matcherPart, "r:"):
		pattern := strings.TrimSpace(strings.TrimPrefix(matcherPart, "r:"))
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errf("rule %q: bad regex: %v", raw, err)
		}
		r.matchType, r.regex = "regex", re

	case strings.HasPrefix(matcherPart, "n:"):
		rest := strings.TrimSpace(strings.TrimPrefix(matcherPart, "n:"))
		fields := strings.Fields(rest)
		compareIdx := indexOf(fields, "compare")
		if compareIdx == -1 || compareIdx+2 >= len(fields) {
			return nil, errf("rule %q: expected \"n:<regex> compare <op> <value>\"", raw)
		}
		pattern := strings.Join(fields[:compareIdx], " ")
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errf("rule %q: bad regex: %v", raw, err)
		}
		op := fields[compareIdx+1]
		valStr := fields[compareIdx+2]
		if op == "between" {
			parts := strings.SplitN(valStr, "..", 2)
			if len(parts) != 2 {
				return nil, errf("rule %q: \"between\" needs \"<lo>..<hi>\"", raw)
			}
			lo, err1 := strconv.ParseFloat(parts[0], 64)
			hi, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 != nil || err2 != nil {
				return nil, errf("rule %q: bad between bounds", raw)
			}
			r.compareLo, r.compareHi = lo, hi
		} else {
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				return nil, errf("rule %q: bad compare value %q", raw, valStr)
			}
			r.compareLo = v
		}
		r.matchType, r.regex, r.compareOp = "numeric", re, op

	case strings.HasPrefix(matcherPart, "perm<="):
		octal := strings.TrimSpace(strings.TrimPrefix(matcherPart, "perm<="))
		v, err := strconv.ParseUint(octal, 8, 32)
		if err != nil {
			return nil, errf("rule %q: bad octal perm %q", raw, octal)
		}
		r.matchType, r.permMax = "perm", os.FileMode(v)

	case strings.HasPrefix(matcherPart, "opts:"):
		list := strings.TrimSpace(strings.TrimPrefix(matcherPart, "opts:"))
		r.matchType, r.opts = "opts", strings.Split(list, ",")

	default:
		return nil, errf("rule %q: unrecognized matcher %q", raw, matcherPart)
	}
	return r, nil
}

// evaluate runs one parsed rule against the live host. ports is only
// consulted by special.go's checks, never by rule evaluation — kept here
// only so callers have one signature to reason about isn't needed; rule
// evaluation never touches port data.
func (r *rule) evaluate() ruleEval {
	switch r.selector {
	case "f":
		return r.evalFile()
	case "c":
		return r.evalCommand()
	case "m":
		return r.evalMount()
	case "sshd":
		return r.evalSSHD()
	}
	return ruleEval{evalFail, "unknown selector"}
}

func (r *rule) evalFile() ruleEval {
	info, statErr := os.Stat(r.target)
	exists := statErr == nil

	if r.matchType == "exists" {
		if r.negate {
			if exists {
				return ruleEval{evalFail, r.target + " exists"}
			}
			return ruleEval{evalPass, r.target + " does not exist"}
		}
		if exists {
			return ruleEval{evalPass, r.target + " exists"}
		}
		return ruleEval{evalFail, r.target + " does not exist"}
	}

	if !exists {
		return ruleEval{evalSkip, r.target + " not present on this host"}
	}

	if r.matchType == "perm" {
		mode := info.Mode().Perm()
		if mode&^r.permMax != 0 {
			return ruleEval{evalFail, r.target + " mode " + mode.String() + " exceeds max " + r.permMax.String()}
		}
		return ruleEval{evalPass, r.target + " mode " + mode.String() + " within limit"}
	}

	data, err := os.ReadFile(r.target)
	if err != nil {
		// Exists per Stat but unreadable (permission denied) — a real,
		// distinct failure mode from "not present", so it must not be
		// silently folded into evalSkip (which would hide a genuine
		// privileged-read problem as if the file were simply absent).
		return ruleEval{evalFail, "cannot read " + r.target + ": " + err.Error()}
	}
	return evalTextRules(r, string(data), r.target)
}

func (r *rule) evalCommand() ruleEval {
	fields := strings.Fields(r.target)
	if len(fields) == 0 {
		return ruleEval{evalFail, "empty command"}
	}
	if _, err := exec.LookPath(fields[0]); err != nil {
		return ruleEval{evalSkip, fields[0] + " not found on this host"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	out, _ := exec.CommandContext(ctx, fields[0], fields[1:]...).CombinedOutput()
	return evalTextRules(r, string(out), "`"+r.target+"`")
}

func (r *rule) evalMount() ruleEval {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ruleEval{evalSkip, "cannot read /proc/mounts"}
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != r.target {
			continue
		}
		have := strings.Split(fields[3], ",")
		haveSet := map[string]bool{}
		for _, o := range have {
			haveSet[o] = true
		}
		var missing []string
		for _, want := range r.opts {
			if !haveSet[strings.TrimSpace(want)] {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			return ruleEval{evalFail, r.target + " missing option(s): " + strings.Join(missing, ",") + " (mounted with " + fields[3] + ")"}
		}
		return ruleEval{evalPass, r.target + " mounted with " + fields[3]}
	}
	return ruleEval{evalSkip, r.target + " is not a separate mount on this host"}
}

func (r *rule) evalSSHD() ruleEval {
	cfg, err := loadSSHDConfig()
	if err != nil {
		return ruleEval{evalSkip, "no sshd_config on this host (sshd not installed?)"}
	}
	val, ok := cfg[r.target]
	if !ok {
		if r.def == "" {
			return ruleEval{evalFail, r.target + " not set in sshd_config"}
		}
		val = r.def
	}
	return evalTextRules(r, val, "sshd "+r.target+"="+val)
}

// evalTextRules applies a rule's regex/numeric matcher to already-resolved
// text content (a file's bytes, a command's output, an sshd directive's
// value) — the three selectors above differ only in how they produce this
// text, not in how it's tested.
func evalTextRules(r *rule, content, label string) ruleEval {
	switch r.matchType {
	case "regex":
		if r.regex.MatchString(content) {
			return ruleEval{evalPass, label + " matches " + r.regex.String()}
		}
		return ruleEval{evalFail, label + " does not match " + r.regex.String()}
	case "notregex":
		if r.regex.MatchString(content) {
			return ruleEval{evalFail, label + " matches " + r.regex.String() + " (should not)"}
		}
		return ruleEval{evalPass, label + " does not match " + r.regex.String()}
	case "numeric":
		m := r.regex.FindStringSubmatch(content)
		if m == nil || len(m) < 2 {
			return ruleEval{evalFail, label + " has no value matching " + r.regex.String()}
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(m[1]), 64)
		if err != nil {
			return ruleEval{evalFail, label + ": captured value not numeric: " + m[1]}
		}
		if compareNumeric(n, r.compareOp, r.compareLo, r.compareHi) {
			return ruleEval{evalPass, label + " = " + m[1]}
		}
		return ruleEval{evalFail, label + " = " + m[1] + " (expected " + compareDesc(r.compareOp, r.compareLo, r.compareHi) + ")"}
	}
	return ruleEval{evalFail, "unsupported matcher on " + label}
}

func compareNumeric(n float64, op string, lo, hi float64) bool {
	switch op {
	case "<=":
		return n <= lo
	case ">=":
		return n >= lo
	case "<":
		return n < lo
	case ">":
		return n > lo
	case "==":
		return n == lo
	case "!=":
		return n != lo
	case "between":
		return n >= lo && n <= hi
	}
	return false
}

func compareDesc(op string, lo, hi float64) string {
	if op == "between" {
		return "between " + strconv.FormatFloat(lo, 'f', -1, 64) + " and " + strconv.FormatFloat(hi, 'f', -1, 64)
	}
	return op + " " + strconv.FormatFloat(lo, 'f', -1, 64)
}

func indexOf(fields []string, target string) int {
	for i, f := range fields {
		if f == target {
			return i
		}
	}
	return -1
}
