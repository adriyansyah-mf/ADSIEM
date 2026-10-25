package detect

import (
	"fmt"
	"regexp"
	"time"
)

const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// DefaultRules ship disabled. Enabling them is an explicit operator decision
// because a blocking rule on a production host can cut off access.
func DefaultRules() []Rule {
	return []Rule{
		{
			Key:       "ssh_bruteforce",
			LogType:   "linux_auth",
			Match:     regexp.MustCompile(`Failed password|Failed none|Invalid user`),
			GroupExpr: regexp.MustCompile(`from (\d{1,3}(?:\.\d{1,3}){3})`),
			Threshold: 5,
			Window:    60 * time.Second,
			Cooldown:  10 * time.Minute,
			Action:    actionBlock,
			BlockFor:  10 * time.Minute,
			Title:     "Local: SSH brute force",
			Severity:  SeverityHigh,
			Source:    "linux_auth",
			enabled:   false,
		},
		{
			Key:       "port_scan",
			LogType:   "linux_network_accept",
			Match:     regexp.MustCompile(`action=network_accept`),
			GroupExpr: regexp.MustCompile(`dst=(\d{1,3}(?:\.\d{1,3}){3})`),
			Threshold: 20,
			Window:    30 * time.Second,
			Cooldown:  15 * time.Minute,
			Action:    actionBlock,
			BlockFor:  15 * time.Minute,
			Title:     "Local: port scan",
			Severity:  SeverityMedium,
			Source:    "linux_network_accept",
			enabled:   false,
		},
		{
			// Windows Security 4625 (failed logon) over the network (LogonType 3:
			// SMB, WinRM...) or RDP (10), as winevent.FormatXML writes it.
			// IpAddress may be IPv4-mapped IPv6. A higher threshold than SSH:
			// mistyped RDP/NLA passwords are common.
			Key:       "windows_logon_bruteforce",
			LogType:   "windows_security",
			Match:     regexp.MustCompile(`^EventID=4625 .*\bLogonType="(?:3|10)"`),
			GroupExpr: regexp.MustCompile(`\bIpAddress="(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})"`),
			Threshold: 10,
			Window:    60 * time.Second,
			Cooldown:  10 * time.Minute,
			Action:    actionBlock,
			BlockFor:  10 * time.Minute,
			Title:     "Local: Windows logon brute force (RDP/SMB)",
			Severity:  SeverityHigh,
			Source:    "windows_security",
			enabled:   false,
		},
		{
			Key:       "webshell_upload",
			LogType:   "apache_access",
			Match: regexp.MustCompile(`(?i)(upload|tmp|files?|images?|shell|cmd|backdoor)[^\s"]*\.(php|jsp|ashx|phtml)\b`),
			GroupExpr: regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})`),
			Threshold: 1,
			Window:    60 * time.Second,
			Cooldown:  30 * time.Minute,
			Action:    actionAlert,
			Title:     "Local: possible web shell upload",
			Severity:  SeverityCritical,
			Source:    "apache_access",
			enabled:   false,
		},
	}
}

func ApplyEnabled(rules []Rule, enabledKeys []string) ([]Rule, error) {
	want := make(map[string]bool, len(enabledKeys))
	for _, k := range enabledKeys {
		want[k] = true
	}

	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if want[r.Key] {
			r.enabled = true
			if err := r.Validate(); err != nil {
				return nil, err
			}
			delete(want, r.Key)
		}
		out = append(out, r)
	}

	for k := range want {
		return nil, fmt.Errorf("local rule %q does not exist", k)
	}
	return out, nil
}
