package sca

import "strings"

// fold combines a check's per-rule results into one Status per its
// condition ("all" | "any" | "none", default "all"). evalSkip results are
// excluded from the vote entirely — a check whose every rule skipped (e.g.
// every candidate config file is absent) reports not_applicable rather than
// a fabricated pass or fail, the same rule this package's checks have
// followed since the original hardcoded-Go implementation.
func fold(condition string, evals []ruleEval) (Status, string) {
	condition = strings.ToLower(strings.TrimSpace(condition))
	if condition == "" {
		condition = "all"
	}

	var voting []ruleEval
	for _, e := range evals {
		if e.status != evalSkip {
			voting = append(voting, e)
		}
	}
	if len(voting) == 0 {
		return StatusNotApplicable, joinDetails(evals)
	}

	passCount := 0
	for _, e := range voting {
		if e.status == evalPass {
			passCount++
		}
	}

	var ok bool
	switch condition {
	case "all":
		ok = passCount == len(voting)
	case "any":
		ok = passCount > 0
	case "none":
		ok = passCount == 0
	default:
		ok = passCount == len(voting)
	}

	if ok {
		return StatusPass, joinDetails(voting)
	}
	return StatusFail, joinDetails(voting)
}

func joinDetails(evals []ruleEval) string {
	details := make([]string, 0, len(evals))
	for _, e := range evals {
		details = append(details, e.detail)
	}
	return strings.Join(details, "; ")
}
