package task

import (
	"fmt"
	"strconv"
	"strings"
)

// eventlogXPath builds the query from validated args, so nothing from the
// artifact parameters is spliced into XPath unchecked.
func eventlogXPath(args map[string]any) (string, error) {
	if x := argString(args, "xpath", ""); x != "" {
		return x, nil
	}
	var conds []string
	var ids []string
	for _, raw := range argStrings(args, "event_ids") {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
			if _, err := strconv.Atoi(part); err != nil {
				return "", fmt.Errorf("event_ids: %q is not a number", part)
			}
			ids = append(ids, "EventID="+part)
		}
	}
	if len(ids) > 0 {
		conds = append(conds, "("+strings.Join(ids, " or ")+")")
	}
	if hours := argInt(args, "hours", 24); hours > 0 {
		conds = append(conds, fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", int64(hours)*3_600_000))
	}
	if len(conds) == 0 {
		return "*", nil
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]", nil
}
