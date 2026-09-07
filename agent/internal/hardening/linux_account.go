package hardening

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func checkPasswordMaxAge(path string) Check {
	const id = "acct-password-maxage"
	const category = "account"
	const title = "Password maximum age is set and reasonable (<=90 days)"

	f, err := os.Open(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no login.defs on this host"}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "PASS_MAX_DAYS" {
			days, err := strconv.Atoi(fields[1])
			if err != nil {
				continue
			}
			if days >= 1 && days <= 90 {
				return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "PASS_MAX_DAYS=" + fields[1]}
			}
			return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "PASS_MAX_DAYS=" + fields[1] + " (expected 1-90)"}
		}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "PASS_MAX_DAYS not set in login.defs"}
}

func checkPasswordComplexity(paths []string) Check {
	const id = "acct-password-complexity"
	const category = "account"
	const title = "Password complexity module (pam_pwquality/pam_cracklib) is configured"

	found := false
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found = true
		content := string(data)
		if strings.Contains(content, "pam_pwquality.so") || strings.Contains(content, "pam_cracklib.so") {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "found in " + p}
		}
	}
	if !found {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no PAM password config file found on this host"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "no pam_pwquality.so/pam_cracklib.so found in PAM password config"}
}

func checkAccountLockout(paths []string) Check {
	const id = "acct-lockout"
	const category = "account"
	const title = "Account lockout on repeated failed logins (pam_faillock/pam_tally2) is configured"

	found := false
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found = true
		content := string(data)
		if strings.Contains(content, "pam_faillock.so") || strings.Contains(content, "pam_tally2.so") {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "found in " + p}
		}
	}
	if !found {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no PAM auth config file found on this host"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "no pam_faillock.so/pam_tally2.so found in PAM auth config"}
}

func checkNoEmptyPasswords(path string) Check {
	const id = "acct-no-empty-password"
	const category = "account"
	const title = "No local account has an empty password"

	f, err := os.Open(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusError, Detail: "cannot read shadow file: " + err.Error()}
	}
	defer f.Close()

	var empty []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "" {
			empty = append(empty, fields[0])
		}
	}
	if len(empty) > 0 {
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "empty password field for: " + strings.Join(empty, ", ")}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "no accounts with an empty password field"}
}

func checkNoDuplicateRootUID(path string) Check {
	const id = "acct-no-duplicate-root"
	const category = "account"
	const title = "No non-root account shares UID 0"

	f, err := os.Open(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no passwd file on this host"}
	}
	defer f.Close()

	var extra []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == "0" && fields[0] != "root" {
			extra = append(extra, fields[0])
		}
	}
	if len(extra) > 0 {
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "UID 0 account(s) besides root: " + strings.Join(extra, ", ")}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "only root has UID 0"}
}
