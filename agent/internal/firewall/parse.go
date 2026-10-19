package firewall

import (
	"strings"
)

func parseNftList(raw string) []Rule {
	var rules []Rule
	inSet := ""
	var collecting []string
	depth := 0

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)

		if len(collecting) == 0 {
			if strings.HasPrefix(trimmed, "set ") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					inSet = fields[1]
				}
				continue
			}
			if !strings.HasPrefix(trimmed, "elements") || !isTrackedSet(inSet) {
				continue
			}
		}

		if !isTrackedSet(inSet) {
			collecting = nil
			continue
		}

		collecting = append(collecting, trimmed)
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth > 0 {
			continue
		}

		body := strings.Join(collecting, " ")
		collecting = nil
		depth = 0

		open := strings.Index(body, "{")
		if open < 0 {
			continue
		}
		body = body[open+1:]
		if close := strings.LastIndex(body, "}"); close >= 0 {
			body = body[:close]
		}

		for _, elem := range splitElements(body, inSet) {
			if r, ok := ruleFromElement(inSet, elem); ok {
				rules = append(rules, r)
			}
		}
	}

	return rules
}

func isTrackedSet(name string) bool {
	switch name {
	case setIPIn, setIPOut, setSvcIn, setSvcOut:
		return true
	}
	return false
}

// splitElements separates set members. Plain address sets are comma-separated.
// Concatenated keys print as "a . b . c timeout 1m", where the separator is
// " . " and never a bare ",", so splitting on commas stays correct; the helper
// exists to keep that assumption in one place and testable.
func splitElements(body, set string) []string {
	_ = set
	var out []string
	for _, part := range strings.Split(body, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ruleFromElement(set, elem string) (Rule, bool) {
	fields := strings.Fields(elem)
	if len(fields) == 0 {
		return Rule{}, false
	}

	r := Rule{Proto: "any", Direction: DirBoth, Action: ActionBlock}

	switch set {
	case setIPIn:
		r.CIDR = fields[0]
		r.Direction = DirInbound
	case setIPOut:
		r.CIDR = fields[0]
		r.Direction = DirOutbound
	case setSvcIn, setSvcOut:
		key := strings.Join(fieldsBeforeAttrs(fields), " ")
		parts := strings.Split(key, " . ")
		if len(parts) < 3 {
			return Rule{}, false
		}
		r.CIDR = strings.TrimSpace(parts[0])
		r.Proto = strings.TrimSpace(parts[1])
		port, ok := atoi(strings.TrimSpace(parts[2]))
		if !ok {
			return Rule{}, false
		}
		r.Port = port
		if set == setSvcIn {
			r.Direction = DirInbound
		} else {
			r.Direction = DirOutbound
		}
	default:
		return Rule{}, false
	}

	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "timeout" {
			if d, ok := parseDuration(fields[i+1]); ok {
				r.TTL = d
			}
		}
	}

	r.ID = r.Key()
	return r, true
}

func fieldsBeforeAttrs(fields []string) []string {
	for i, f := range fields {
		if f == "timeout" || f == "expires" {
			return fields[:i]
		}
	}
	return fields
}
