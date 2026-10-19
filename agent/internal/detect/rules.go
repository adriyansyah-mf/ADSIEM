package detect

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type action int

const (
	actionAlert action = iota
	actionBlock
)

// Rule is a local threshold rule. It is deliberately a small, explicit schema
// rather than a Sigma subset: the server already evaluates full Sigma rules
// with Redis-backed state, and this engine exists to keep working when that
// server is unreachable.
type Rule struct {
	Key       string
	LogType   string
	Match     *regexp.Regexp
	GroupBy   string
	GroupExpr *regexp.Regexp
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
	Action    action
	BlockFor  time.Duration
	Title     string
	Severity  string
	Source    string
	enabled   bool
}

func (r Rule) Enabled() bool { return r.enabled }

func (r Rule) Validate() error {
	if r.Key == "" {
		return fmt.Errorf("rule key is required")
	}
	if r.LogType == "" {
		return fmt.Errorf("rule %s: log_type is required", r.Key)
	}
	if r.Match == nil {
		return fmt.Errorf("rule %s: match pattern is required", r.Key)
	}
	if r.Threshold < 1 {
		return fmt.Errorf("rule %s: threshold must be >= 1", r.Key)
	}
	if r.Window <= 0 {
		return fmt.Errorf("rule %s: window must be > 0", r.Key)
	}
	if r.GroupBy == "" && r.GroupExpr == nil {
		return fmt.Errorf("rule %s: group_by or group_expr is required", r.Key)
	}
	if r.Action == actionBlock && r.BlockFor <= 0 {
		return fmt.Errorf("rule %s: block_for must be > 0 for a blocking rule", r.Key)
	}
	return nil
}

type fieldLookup map[string]string

// extract returns key=value pairs from a log line. Both the agent's own
// structured events (ts=... pid=... dst=...) and sshd/apache lines benefit, so
// matching stays declarative instead of one bespoke parser per source.
func extract(line string) fieldLookup {
	out := make(fieldLookup)
	for _, field := range strings.Fields(line) {
		k, v, ok := strings.Cut(field, "=")
		if !ok || k == "" || v == "" {
			continue
		}
		out[strings.ToLower(k)] = strings.Trim(v, `"`)
	}
	return out
}

// group determines the counter key. GroupExpr wins when set: syslog lines
// (sshd, apache) carry no key=value pairs, so the address has to be pulled out
// of free text. Without either, the event cannot be attributed and is skipped
// rather than pooled into a catch-all bucket that would fire on unrelated
// traffic.
func (r Rule) group(line string) (string, bool) {
	if r.GroupExpr != nil {
		m := r.GroupExpr.FindStringSubmatch(line)
		if len(m) < 2 || m[1] == "" {
			return "", false
		}
		return m[1], true
	}
	if r.GroupBy == "" {
		return "_all", true
	}
	v, ok := extract(line)[strings.ToLower(r.GroupBy)]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

func (r Rule) matches(logType, line string) (string, bool) {
	if !strings.EqualFold(r.LogType, logType) {
		return "", false
	}
	if !r.Match.MatchString(line) {
		return "", false
	}
	return r.group(line)
}
