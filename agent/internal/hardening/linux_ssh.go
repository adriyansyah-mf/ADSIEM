package hardening

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// sshdConfigDir is where a relative Include argument is resolved from,
// matching sshd's own behavior.
const sshdConfigDir = "/etc/ssh"

func parseSSHDConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string)
	scanSSHDConfig(f, result)
	return result, nil
}

// parseSSHDConfigInto opens path and merges its directives into result,
// expanding any Include directive inline (recursively) at the point it
// appears — matching sshd's own top-to-bottom, first-occurrence-wins
// processing, whether the directive comes from the main file or one it
// includes. Errors opening an included file are ignored, same as sshd's
// own leniency about optional Include globs.
func parseSSHDConfigInto(path string, result map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanSSHDConfig(f, result)
}

func scanSSHDConfig(f *os.File, result map[string]string) {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "include" {
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(sshdConfigDir, pattern)
				}
				matches, err := filepath.Glob(pattern)
				if err != nil {
					continue
				}
				sort.Strings(matches)
				for _, m := range matches {
					parseSSHDConfigInto(m, result)
				}
			}
			continue
		}
		// sshd uses the first occurrence of a directive; later ones are ignored.
		if _, exists := result[key]; !exists {
			result[key] = fields[1]
		}
	}
}

func checkSSHNoRootLogin(path string) Check {
	const id = "ssh-no-root-login"
	const category = "ssh"
	const title = "SSH root login is disabled (PermitRootLogin no)"

	cfg, err := parseSSHDConfig(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no sshd_config on this host (sshd not installed?)"}
	}
	val, ok := cfg["permitrootlogin"]
	if !ok {
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "PermitRootLogin not set (OpenSSH default is 'prohibit-password', not 'no')"}
	}
	if val == "no" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "PermitRootLogin no"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "PermitRootLogin " + val}
}

func checkSSHNoPasswordAuth(path string) Check {
	const id = "ssh-no-password-auth"
	const category = "ssh"
	const title = "SSH password authentication is disabled (key-only)"

	cfg, err := parseSSHDConfig(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no sshd_config on this host (sshd not installed?)"}
	}
	val, ok := cfg["passwordauthentication"]
	if ok && val == "no" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "PasswordAuthentication no"}
	}
	if !ok {
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "PasswordAuthentication not set (OpenSSH default is 'yes')"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "PasswordAuthentication " + val}
}

func checkSSHProtocol2(path string) Check {
	const id = "ssh-protocol-2"
	const category = "ssh"
	const title = "SSH protocol is version 2 only"

	cfg, err := parseSSHDConfig(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no sshd_config on this host (sshd not installed?)"}
	}
	val, ok := cfg["protocol"]
	if !ok {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "Protocol not set — modern OpenSSH defaults to 2-only"}
	}
	if val == "2" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "Protocol 2"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "Protocol " + val}
}

func checkSSHMaxAuthTries(path string) Check {
	const id = "ssh-max-auth-tries"
	const category = "ssh"
	const title = "SSH MaxAuthTries is 4 or fewer"

	cfg, err := parseSSHDConfig(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "no sshd_config on this host (sshd not installed?)"}
	}
	val, ok := cfg["maxauthtries"]
	if !ok {
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "MaxAuthTries not set (OpenSSH default is 6)"}
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusError, Detail: "MaxAuthTries value not a number: " + val}
	}
	if n <= 4 {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "MaxAuthTries " + val}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "MaxAuthTries " + val + " (expected <=4)"}
}
