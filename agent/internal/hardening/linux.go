package hardening

import "github.com/siem-platform/agent/internal/sca"

// Collect runs every check in every loaded SCA policy (the embedded default
// plus anything under sca.ExtraPolicyDir) and returns the aggregate report.
// openPorts is the same port list the hygiene collector already gathered —
// passed in rather than re-scanned here to avoid duplicating /proc/net/tcp
// parsing in two packages.
//
// The actual check logic (previously ~20 hardcoded Go functions across this
// package's linux_*.go files) now lives in the internal/sca package as data
// — a YAML policy with a small rule DSL — so tuning or adding a check no
// longer requires rebuilding and redeploying the agent binary. This
// function only translates between the two packages' equivalent Status/
// Check/PortInfo types, which are kept independent so hardening's public
// shape (already persisted server-side) never has to change when sca's
// internals do.
func Collect(openPorts []PortInfo) *Report {
	policies, err := sca.LoadPolicies()
	if err != nil {
		// A broken embedded policy is a build-time bug, not a host
		// condition — report it as a single error check rather than
		// panicking the hygiene collector (which recovers panics anyway,
		// but an explicit error check is more informative than an empty
		// report).
		return &Report{Checks: []Check{{
			ID: "sca-policy-load", Category: "sca", Title: "SCA policies loaded successfully",
			Status: StatusError, Detail: err.Error(),
		}}}
	}

	scaPorts := make([]sca.PortInfo, len(openPorts))
	for i, p := range openPorts {
		scaPorts[i] = sca.PortInfo{Port: p.Port, Proto: p.Proto, State: p.State}
	}

	results := sca.Evaluate(policies, scaPorts)
	r := &Report{Checks: make([]Check, len(results))}
	for i, res := range results {
		r.Checks[i] = Check{
			ID: res.ID, Category: res.Category, Title: res.Title,
			Status: Status(res.Status), Detail: res.Detail,
		}
	}
	return r
}
