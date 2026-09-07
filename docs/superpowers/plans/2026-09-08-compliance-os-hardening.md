# Compliance Manager OS-Level Hardening Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Compliance Manager real, agent-collected CIS-Benchmark-style OS hardening evidence (account/password policy, network/firewall, SSH, kernel/filesystem) instead of its current shallow proxies, for Linux endpoints, with a shape that can grow to Windows later.

**Architecture:** A new Go package `agent/internal/hardening/` runs ~16 local checks and attaches the results to the existing hygiene snapshot report. The backend stores them in a new JSONB column on `hygiene_snapshots` and `compliance.py`'s checks read that data to compute richer control statuses, falling back to the old shallow logic for hosts running an older agent that hasn't reported hardening data yet.

**Tech Stack:** Go 1.25 (agent), Python/FastAPI/SQLAlchemy (server-api), Postgres JSONB.

**Spec:** `docs/superpowers/specs/2026-09-08-compliance-os-hardening-design.md`

## Global Constraints

- Every check that reads a config/proc file treats "file missing" as `not_applicable`, never `fail` (spec §Error handling).
- A single failed check must never take down hygiene collection — the whole hardening pass is recoverable (spec §Error handling).
- Hosts on an older agent version (no `hardening_checks` data) must not regress to a worse compliance view than they have today — `compliance.py`'s two migrated checks keep their old logic as a fallback (spec §Error handling).
- Linux-only for v1; every type in `agent/internal/hardening/types.go` must stay OS-agnostic (no Linux-specific fields) so a future `windows.go` needs no schema change (spec §Scope).

---

### Task 1: Account/password hardening checks (Go)

**Files:**
- Create: `agent/internal/hardening/types.go`
- Create: `agent/internal/hardening/linux_account.go`
- Create: `agent/internal/hardening/linux_account_test.go`

**Interfaces:**
- Produces: `type Status string` with consts `StatusPass, StatusFail, StatusNotApplicable, StatusError`; `type Check struct{ID, Category, Title string; Status Status; Detail string}` (all JSON-tagged lowercase); `type Report struct{ Checks []Check }`; `type PortInfo struct{ Port int; Proto, State string }`. Produces 5 functions: `checkPasswordMaxAge(path string) Check`, `checkPasswordComplexity(paths []string) Check`, `checkAccountLockout(paths []string) Check`, `checkNoEmptyPasswords(path string) Check`, `checkNoDuplicateRootUID(path string) Check`.
- Consumes: nothing (first task).

- [ ] **Step 1: Write `types.go`**

```go
package hardening

// Status is OS-agnostic — a future windows.go reports the same three-state
// result, so no schema change is needed to add that platform later.
type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusNotApplicable Status = "not_applicable"
	StatusError         Status = "error"
)

type Check struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
}

type Report struct {
	Checks []Check `json:"checks"`
}

// PortInfo mirrors the fields hygiene.OpenPort already carries. Kept as a
// separate type so this package never imports hygiene — hygiene imports
// hardening (to attach checks to its report), not the other way around.
type PortInfo struct {
	Port  int
	Proto string
	State string
}
```

- [ ] **Step 2: Write the failing tests**

```go
package hardening

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTemp: %v", err)
	}
	return path
}

func TestCheckPasswordMaxAge(t *testing.T) {
	pass := writeTemp(t, "login.defs", "PASS_MAX_DAYS\t90\n")
	if c := checkPasswordMaxAge(pass); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	fail := writeTemp(t, "login.defs", "PASS_MAX_DAYS\t99999\n")
	if c := checkPasswordMaxAge(fail); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	missing := writeTemp(t, "login.defs", "# no directive here\n")
	if c := checkPasswordMaxAge(missing); c.Status != StatusFail {
		t.Fatalf("expected fail when directive absent, got %s", c.Status)
	}

	if c := checkPasswordMaxAge("/nonexistent/login.defs"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable for missing file, got %s", c.Status)
	}
}

func TestCheckPasswordComplexity(t *testing.T) {
	good := writeTemp(t, "common-password", "password requisite pam_pwquality.so retry=3\n")
	if c := checkPasswordComplexity([]string{good}); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "common-password", "password required pam_unix.so\n")
	if c := checkPasswordComplexity([]string{bad}); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkPasswordComplexity([]string{"/nonexistent/a", "/nonexistent/b"}); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable when no candidate file exists, got %s", c.Status)
	}
}

func TestCheckAccountLockout(t *testing.T) {
	good := writeTemp(t, "common-auth", "auth required pam_faillock.so preauth\n")
	if c := checkAccountLockout([]string{good}); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "common-auth", "auth required pam_unix.so\n")
	if c := checkAccountLockout([]string{bad}); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckNoEmptyPasswords(t *testing.T) {
	good := writeTemp(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nuser:$6$def:19000:0:99999:7:::\n")
	if c := checkNoEmptyPasswords(good); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n")
	c := checkNoEmptyPasswords(bad)
	if c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkNoEmptyPasswords("/nonexistent/shadow"); c.Status != StatusError {
		t.Fatalf("expected error for unreadable shadow file, got %s", c.Status)
	}
}

func TestCheckNoDuplicateRootUID(t *testing.T) {
	good := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n")
	if c := checkNoDuplicateRootUID(good); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/bash\n")
	c := checkNoDuplicateRootUID(bad)
	if c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: FAIL — `checkPasswordMaxAge` etc. undefined (linux_account.go doesn't exist yet).

- [ ] **Step 4: Write `linux_account.go`**

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: PASS (all `TestCheck*` in this file)

- [ ] **Step 6: Commit**

```bash
git add agent/internal/hardening/types.go agent/internal/hardening/linux_account.go agent/internal/hardening/linux_account_test.go
git commit -m "feat(agent): add account/password hardening checks"
```

---

### Task 2: Network/firewall hardening checks (Go)

**Files:**
- Create: `agent/internal/hardening/linux_network.go`
- Create: `agent/internal/hardening/linux_network_test.go`

**Interfaces:**
- Consumes: `Status`, `Check`, `PortInfo` from Task 1's `types.go`.
- Produces: `checkFirewallActive() Check`, `checkIPForwardDisabled(path string) Check`, `checkNoLegacyServices(ports []PortInfo) Check`.

- [ ] **Step 1: Write the failing tests**

```go
package hardening

import "testing"

func TestCheckIPForwardDisabled(t *testing.T) {
	disabled := writeTemp(t, "ip_forward", "0\n")
	if c := checkIPForwardDisabled(disabled); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	enabled := writeTemp(t, "ip_forward", "1\n")
	if c := checkIPForwardDisabled(enabled); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkIPForwardDisabled("/nonexistent/ip_forward"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", c.Status)
	}
}

func TestCheckNoLegacyServices(t *testing.T) {
	clean := []PortInfo{{Port: 443, Proto: "tcp", State: "listen"}, {Port: 22, Proto: "tcp", State: "listen"}}
	if c := checkNoLegacyServices(clean); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	withTelnet := []PortInfo{{Port: 23, Proto: "tcp", State: "listen"}, {Port: 443, Proto: "tcp", State: "listen"}}
	c := checkNoLegacyServices(withTelnet)
	if c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	notListening := []PortInfo{{Port: 23, Proto: "tcp", State: "closed"}}
	if c := checkNoLegacyServices(notListening); c.Status != StatusPass {
		t.Fatalf("expected pass for a non-listening legacy port, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckFirewallActive_ReturnsValidStatus(t *testing.T) {
	// checkFirewallActive shells out to real system firewall tools, so this
	// is a smoke test (valid shape), not a deterministic pass/fail test —
	// mocking exec.Command would need infrastructure this repo doesn't have.
	c := checkFirewallActive()
	switch c.Status {
	case StatusPass, StatusFail, StatusNotApplicable, StatusError:
	default:
		t.Fatalf("unexpected status: %q", c.Status)
	}
	if c.ID != "net-firewall-active" {
		t.Fatalf("unexpected ID: %q", c.ID)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: FAIL — `checkIPForwardDisabled`, `checkNoLegacyServices`, `checkFirewallActive` undefined.

- [ ] **Step 3: Write `linux_network.go`**

```go
package hardening

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var insecurePorts = map[int]string{
	21:   "FTP (unencrypted)",
	23:   "Telnet",
	512:  "rexec",
	513:  "rlogin",
	514:  "rsh",
	6000: "X11",
}

func checkFirewallActive() Check {
	const id = "net-firewall-active"
	const category = "network"
	const title = "A firewall service is active with at least a default policy"

	if out, err := exec.Command("firewall-cmd", "--state").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "running" {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "firewalld is running"}
		}
	}
	if out, err := exec.Command("ufw", "status").Output(); err == nil {
		if strings.Contains(string(out), "Status: active") {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "ufw is active"}
		}
	}
	if out, err := exec.Command("nft", "list", "ruleset").Output(); err == nil {
		if strings.TrimSpace(string(out)) != "" {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "nftables has an active ruleset"}
		}
	}
	if out, err := exec.Command("iptables", "-S").Output(); err == nil {
		s := string(out)
		if strings.Contains(s, "-P INPUT DROP") || strings.Contains(s, "-P INPUT REJECT") {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "iptables INPUT policy is DROP/REJECT"}
		}
		if strings.TrimSpace(s) != "" {
			return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "iptables has rules but INPUT policy is not DROP/REJECT"}
		}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "no active firewall backend detected (firewalld/ufw/nftables/iptables)"}
}

func checkIPForwardDisabled(path string) Check {
	const id = "net-ip-forward-disabled"
	const category = "network"
	const title = "IPv4 forwarding is disabled"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read ip_forward sysctl"}
	}
	val := strings.TrimSpace(string(data))
	if val == "0" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "net.ipv4.ip_forward=0"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "net.ipv4.ip_forward=" + val + " (expected 0 unless this host is a designated router)"}
}

func checkNoLegacyServices(ports []PortInfo) Check {
	const id = "net-no-legacy-services"
	const category = "network"
	const title = "No legacy/insecure network services are listening"

	var found []string
	for _, p := range ports {
		name, bad := insecurePorts[p.Port]
		if !bad {
			continue
		}
		state := strings.ToLower(p.State)
		if state == "listen" || state == "listening" {
			found = append(found, name+" ("+strconv.Itoa(p.Port)+")")
		}
	}
	if len(found) > 0 {
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "listening: " + strings.Join(found, ", ")}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "no legacy/insecure services found among " + strconv.Itoa(len(ports)) + " open port(s)"}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/internal/hardening/linux_network.go agent/internal/hardening/linux_network_test.go
git commit -m "feat(agent): add network/firewall hardening checks"
```

---

### Task 3: SSH hardening checks (Go)

**Files:**
- Create: `agent/internal/hardening/linux_ssh.go`
- Create: `agent/internal/hardening/linux_ssh_test.go`

**Interfaces:**
- Consumes: `Status`, `Check` from Task 1.
- Produces: `checkSSHNoRootLogin(path string) Check`, `checkSSHNoPasswordAuth(path string) Check`, `checkSSHProtocol2(path string) Check`, `checkSSHMaxAuthTries(path string) Check`. Also produces the unexported helper `parseSSHDConfig(path string) (map[string]string, error)`, used only within this file.

- [ ] **Step 1: Write the failing tests**

```go
package hardening

import "testing"

func TestCheckSSHNoRootLogin(t *testing.T) {
	hardened := writeTemp(t, "sshd_config", "PermitRootLogin no\n")
	if c := checkSSHNoRootLogin(hardened); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unhardened := writeTemp(t, "sshd_config", "PermitRootLogin yes\n")
	if c := checkSSHNoRootLogin(unhardened); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	unset := writeTemp(t, "sshd_config", "Port 22\n")
	if c := checkSSHNoRootLogin(unset); c.Status != StatusFail {
		t.Fatalf("expected fail when unset (OpenSSH default is not 'no'), got %s", c.Status)
	}

	if c := checkSSHNoRootLogin("/nonexistent/sshd_config"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", c.Status)
	}
}

func TestCheckSSHNoPasswordAuth(t *testing.T) {
	hardened := writeTemp(t, "sshd_config", "PasswordAuthentication no\n")
	if c := checkSSHNoPasswordAuth(hardened); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unhardened := writeTemp(t, "sshd_config", "PasswordAuthentication yes\n")
	if c := checkSSHNoPasswordAuth(unhardened); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckSSHProtocol2(t *testing.T) {
	explicit := writeTemp(t, "sshd_config", "Protocol 2\n")
	if c := checkSSHProtocol2(explicit); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	omitted := writeTemp(t, "sshd_config", "Port 22\n")
	if c := checkSSHProtocol2(omitted); c.Status != StatusPass {
		t.Fatalf("expected pass when omitted (modern OpenSSH defaults to 2), got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckSSHMaxAuthTries(t *testing.T) {
	good := writeTemp(t, "sshd_config", "MaxAuthTries 4\n")
	if c := checkSSHMaxAuthTries(good); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	bad := writeTemp(t, "sshd_config", "MaxAuthTries 6\n")
	if c := checkSSHMaxAuthTries(bad); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	unset := writeTemp(t, "sshd_config", "Port 22\n")
	if c := checkSSHMaxAuthTries(unset); c.Status != StatusFail {
		t.Fatalf("expected fail when unset (OpenSSH default is 6), got %s", c.Status)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: FAIL — SSH check functions undefined.

- [ ] **Step 3: Write `linux_ssh.go`**

```go
package hardening

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func parseSSHDConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string)
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
		// sshd uses the first occurrence of a directive; later ones are ignored.
		if _, exists := result[key]; !exists {
			result[key] = fields[1]
		}
	}
	return result, nil
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/internal/hardening/linux_ssh.go agent/internal/hardening/linux_ssh_test.go
git commit -m "feat(agent): add SSH hardening checks"
```

---

### Task 4: Kernel/filesystem hardening checks (Go)

**Files:**
- Create: `agent/internal/hardening/linux_kernel.go`
- Create: `agent/internal/hardening/linux_kernel_test.go`

**Interfaces:**
- Consumes: `Status`, `Check` from Task 1.
- Produces: `checkKernelASLR(path string) Check`, `checkKernelPtraceScope(path string) Check`, `checkKernelCoreDumpRestricted(path string) Check`, `checkTmpNoExec(mountsPath string) Check`.

- [ ] **Step 1: Write the failing tests**

```go
package hardening

import "testing"

func TestCheckKernelASLR(t *testing.T) {
	full := writeTemp(t, "randomize_va_space", "2\n")
	if c := checkKernelASLR(full); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	off := writeTemp(t, "randomize_va_space", "0\n")
	if c := checkKernelASLR(off); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckKernelPtraceScope(t *testing.T) {
	restricted := writeTemp(t, "ptrace_scope", "1\n")
	if c := checkKernelPtraceScope(restricted); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unrestricted := writeTemp(t, "ptrace_scope", "0\n")
	if c := checkKernelPtraceScope(unrestricted); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	if c := checkKernelPtraceScope("/nonexistent/ptrace_scope"); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable when Yama LSM absent, got %s", c.Status)
	}
}

func TestCheckKernelCoreDumpRestricted(t *testing.T) {
	restricted := writeTemp(t, "suid_dumpable", "0\n")
	if c := checkKernelCoreDumpRestricted(restricted); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unrestricted := writeTemp(t, "suid_dumpable", "1\n")
	if c := checkKernelCoreDumpRestricted(unrestricted); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}
}

func TestCheckTmpNoExec(t *testing.T) {
	hardened := writeTemp(t, "mounts", "tmpfs /tmp tmpfs rw,noexec,nosuid,nodev 0 0\n")
	if c := checkTmpNoExec(hardened); c.Status != StatusPass {
		t.Fatalf("expected pass, got %s (%s)", c.Status, c.Detail)
	}

	unhardened := writeTemp(t, "mounts", "tmpfs /tmp tmpfs rw,relatime 0 0\n")
	if c := checkTmpNoExec(unhardened); c.Status != StatusFail {
		t.Fatalf("expected fail, got %s (%s)", c.Status, c.Detail)
	}

	notSeparate := writeTemp(t, "mounts", "/dev/sda1 / ext4 rw,relatime 0 0\n")
	if c := checkTmpNoExec(notSeparate); c.Status != StatusNotApplicable {
		t.Fatalf("expected not_applicable when /tmp isn't its own mount, got %s", c.Status)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: FAIL — kernel check functions undefined.

- [ ] **Step 3: Write `linux_kernel.go`**

```go
package hardening

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func checkKernelASLR(path string) Check {
	const id = "kernel-aslr-enabled"
	const category = "kernel"
	const title = "Full ASLR is enabled (kernel.randomize_va_space=2)"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read randomize_va_space sysctl"}
	}
	val := strings.TrimSpace(string(data))
	if val == "2" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "kernel.randomize_va_space=2"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "kernel.randomize_va_space=" + val + " (expected 2)"}
}

func checkKernelPtraceScope(path string) Check {
	const id = "kernel-ptrace-restricted"
	const category = "kernel"
	const title = "Ptrace scope restricts cross-process debugging (kernel.yama.ptrace_scope>=1)"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "Yama LSM not present on this kernel"}
	}
	val := strings.TrimSpace(string(data))
	n, err := strconv.Atoi(val)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusError, Detail: "unexpected value: " + val}
	}
	if n >= 1 {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "kernel.yama.ptrace_scope=" + val}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "kernel.yama.ptrace_scope=0 (unrestricted)"}
}

func checkKernelCoreDumpRestricted(path string) Check {
	const id = "kernel-coredump-restricted"
	const category = "kernel"
	const title = "Core dumps from setuid programs are restricted (fs.suid_dumpable=0)"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read suid_dumpable sysctl"}
	}
	val := strings.TrimSpace(string(data))
	if val == "0" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "fs.suid_dumpable=0"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "fs.suid_dumpable=" + val + " (expected 0)"}
}

func checkTmpNoExec(mountsPath string) Check {
	const id = "fs-tmp-noexec"
	const category = "kernel"
	const title = "/tmp, if its own mount, is mounted noexec,nosuid"

	f, err := os.Open(mountsPath)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read mounts table"}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[1] != "/tmp" {
			continue
		}
		opts := strings.Split(fields[3], ",")
		hasNoExec, hasNoSuid := false, false
		for _, o := range opts {
			if o == "noexec" {
				hasNoExec = true
			}
			if o == "nosuid" {
				hasNoSuid = true
			}
		}
		if hasNoExec && hasNoSuid {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "/tmp mounted with " + fields[3]}
		}
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "/tmp mounted without noexec,nosuid: " + fields[3]}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "/tmp is not a separate mount on this host"}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/internal/hardening/linux_kernel.go agent/internal/hardening/linux_kernel_test.go
git commit -m "feat(agent): add kernel/filesystem hardening checks"
```

---

### Task 5: Aggregate entrypoint and wire into the hygiene collector (Go)

**Files:**
- Create: `agent/internal/hardening/linux.go`
- Create: `agent/internal/hardening/linux_test.go`
- Modify: `agent/internal/hygiene/types.go`
- Modify: `agent/internal/hygiene/collector.go:13-32` (the `Collect` function)

**Interfaces:**
- Consumes: all check functions from Tasks 1-4.
- Produces: `func Collect(openPorts []PortInfo) *Report` — the only exported entrypoint other packages use.

- [ ] **Step 1: Write the failing test**

```go
package hardening

import "testing"

func TestCollect_ReturnsAllSixteenChecks(t *testing.T) {
	r := Collect(nil)
	if len(r.Checks) != 16 {
		t.Fatalf("expected 16 checks, got %d", len(r.Checks))
	}
	seen := make(map[string]bool)
	for _, c := range r.Checks {
		if seen[c.ID] {
			t.Fatalf("duplicate check ID: %s", c.ID)
		}
		seen[c.ID] = true
		if c.Category == "" || c.Title == "" {
			t.Fatalf("check %s missing category or title", c.ID)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test ./internal/hardening/... -run TestCollect -v`
Expected: FAIL — `Collect` undefined.

- [ ] **Step 3: Write `linux.go`**

```go
package hardening

const (
	loginDefsPath   = "/etc/login.defs"
	shadowPath      = "/etc/shadow"
	passwdPath      = "/etc/passwd"
	sshdConfigPath  = "/etc/ssh/sshd_config"
	ipForwardPath   = "/proc/sys/net/ipv4/ip_forward"
	aslrPath        = "/proc/sys/kernel/randomize_va_space"
	ptraceScopePath = "/proc/sys/kernel/yama/ptrace_scope"
	suidDumpPath    = "/proc/sys/fs/suid_dumpable"
	mountsPath      = "/proc/mounts"
)

var pamPasswordPaths = []string{"/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}
var pamAuthPaths = []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}

// Collect runs every v1 Linux hardening check and returns the aggregate
// report. openPorts is the same port list the hygiene collector already
// gathered — passed in rather than re-scanned here to avoid duplicating
// /proc/net/tcp parsing in two packages.
func Collect(openPorts []PortInfo) *Report {
	r := &Report{}
	r.Checks = append(r.Checks,
		checkPasswordMaxAge(loginDefsPath),
		checkPasswordComplexity(pamPasswordPaths),
		checkAccountLockout(pamAuthPaths),
		checkNoEmptyPasswords(shadowPath),
		checkNoDuplicateRootUID(passwdPath),
		checkFirewallActive(),
		checkIPForwardDisabled(ipForwardPath),
		checkNoLegacyServices(openPorts),
		checkSSHNoRootLogin(sshdConfigPath),
		checkSSHNoPasswordAuth(sshdConfigPath),
		checkSSHProtocol2(sshdConfigPath),
		checkSSHMaxAuthTries(sshdConfigPath),
		checkKernelASLR(aslrPath),
		checkKernelPtraceScope(ptraceScopePath),
		checkKernelCoreDumpRestricted(suidDumpPath),
		checkTmpNoExec(mountsPath),
	)
	return r
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test ./internal/hardening/... -v`
Expected: PASS (every test file in the package, ~20 test functions total)

- [ ] **Step 5: Add `HardeningChecks` to the hygiene report and wire collection in, with panic recovery**

Read `agent/internal/hygiene/types.go` first to get the current import block, then edit:

```go
package hygiene

import "github.com/siem-platform/agent/internal/hardening"

type DiskPartition struct {
	Mount   string  `json:"mount"`
	TotalMB int64   `json:"total_mb"`
	UsedMB  int64   `json:"used_mb"`
	UsePct  float64 `json:"use_pct"`
}

type OpenPort struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	State string `json:"state"`
}

type LocalUser struct {
	Name  string `json:"name"`
	Shell string `json:"shell"`
	UID   int    `json:"uid"`
}

type Issue struct {
	Severity string `json:"severity"` // critical/high/medium/low
	Category string `json:"category"` // disk/memory/port/user
	Message  string `json:"message"`
}

type InstalledPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"` // dpkg, apk, rpm
}

type Report struct {
	AgentID         string             `json:"agent_id"`
	Hostname        string             `json:"hostname"`
	OSName          string             `json:"os_name"`
	OSVersion       string             `json:"os_version"`
	Kernel          string             `json:"kernel"`
	Arch            string             `json:"arch"`
	UptimeSecs      int64              `json:"uptime_seconds"`
	CPUCount        int                `json:"cpu_count"`
	MemTotalMB      int64              `json:"mem_total_mb"`
	MemUsedMB       int64              `json:"mem_used_mb"`
	Disk            []DiskPartition    `json:"disk_partitions"`
	OpenPorts       []OpenPort         `json:"open_ports"`
	Users           []LocalUser        `json:"users"`
	Packages        []InstalledPackage `json:"packages"`
	Score           int                `json:"hygiene_score"`
	Issues          []Issue            `json:"issues"`
	HardeningChecks []hardening.Check  `json:"hardening_checks"`
	CollectedAt     string             `json:"collected_at"`
}
```

Then modify `agent/internal/hygiene/collector.go`'s `Collect` function (currently lines 13-32) to call the new collector after ports are gathered, guarded by `recover()` so a panic in hardening collection never breaks the hygiene report:

```go
func Collect(agentID, hostname string) (*Report, error) {
	r := &Report{
		AgentID:     agentID,
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}

	collectOS(r)
	collectUptime(r)
	collectMemory(r)
	collectCPU(r)
	collectDisk(r)
	collectPorts(r)
	collectUsers(r)
	collectPackages(r)
	collectHardening(r)
	score(r)

	return r, nil
}

// collectHardening never lets a panic in the hardening collector take down
// the rest of the hygiene report — HardeningChecks just stays nil and the
// report still sends.
func collectHardening(r *Report) {
	defer func() {
		recover()
	}()
	ports := make([]hardening.PortInfo, len(r.OpenPorts))
	for i, p := range r.OpenPorts {
		ports[i] = hardening.PortInfo{Port: p.Port, Proto: p.Proto, State: p.State}
	}
	hr := hardening.Collect(ports)
	r.HardeningChecks = hr.Checks
}
```

Add `"github.com/siem-platform/agent/internal/hardening"` to `collector.go`'s import block alongside the existing `bufio`, `os`, `runtime`, `strconv`, `strings`, `syscall`, `time` imports.

- [ ] **Step 6: Build the whole agent to verify it compiles**

Run: `cd agent && go build ./...`
Expected: exits 0, no errors.

- [ ] **Step 7: Commit**

```bash
git add agent/internal/hardening/linux.go agent/internal/hardening/linux_test.go agent/internal/hygiene/types.go agent/internal/hygiene/collector.go
git commit -m "feat(agent): wire OS hardening checks into the hygiene report"
```

---

### Task 6: Persist hardening_checks on the backend (Python)

**Files:**
- Modify: `server-api/app/models/models.py` (the `HygieneSnapshot` class, around line 244-264)
- Modify: `server-api/app/main.py` (add a new `_migrate_*` function and register it)
- Modify: `server-api/app/schemas/schemas.py` (`HygieneSnapshotIn` and `HygieneSnapshotOut`, around line 509-549)
- Modify: `server-api/app/api/routes/hygiene.py:106-124` (the `ingest_hygiene` handler)

**Interfaces:**
- Produces: `HygieneSnapshot.hardening_checks` (JSONB column, list of dicts shaped `{id, category, title, status, detail}` — matches the Go `Check` struct's JSON tags exactly).
- Consumes: nothing new from other tasks — this is the backend counterpart of Task 5's wire format.

- [ ] **Step 1: Add the column to the model**

In `server-api/app/models/models.py`, find this line inside `class HygieneSnapshot(Base):`:

```python
    packages        = Column(JSONB, nullable=False, default=list)
```

Add immediately after it:

```python
    hardening_checks = Column(JSONB, nullable=False, default=list)
```

- [ ] **Step 2: Add the migration**

In `server-api/app/main.py`, add this function near the other `_migrate_*` functions (e.g. right after `_migrate_agent_telemetry_columns`):

```python
async def _migrate_hygiene_hardening_column() -> None:
    """OS-level hardening checks (docs/superpowers/specs/2026-09-08-compliance-os-hardening-design.md)
    — CIS-Benchmark-style checks the agent runs locally (password policy,
    firewall, SSH hardening, kernel hardening), reported alongside the
    existing hygiene snapshot."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE hygiene_snapshots
            ADD COLUMN IF NOT EXISTS hardening_checks JSONB NOT NULL DEFAULT '[]'::jsonb
        """))
```

Then find the `lifespan` function's list of awaited migrations (ends with `await _migrate_agent_telemetry_columns()`) and add a line after it:

```python
        await _migrate_agent_telemetry_columns()
        await _migrate_hygiene_hardening_column()
```

- [ ] **Step 3: Extend the schemas**

In `server-api/app/schemas/schemas.py`, in `HygieneSnapshotIn`, find:

```python
    packages: list[dict] | None = []
    collected_at: str | None = None
```

Replace with:

```python
    packages: list[dict] | None = []
    hardening_checks: list[dict] | None = []
    collected_at: str | None = None
```

In `HygieneSnapshotOut`, find:

```python
    packages: list[dict]
    collected_at: datetime
```

Replace with:

```python
    packages: list[dict]
    hardening_checks: list[dict]
    collected_at: datetime
```

- [ ] **Step 4: Persist it on ingest**

In `server-api/app/api/routes/hygiene.py`, in `ingest_hygiene`, find:

```python
        issues=body.issues or [],
        packages=body.packages or [],
    )
```

Replace with:

```python
        issues=body.issues or [],
        packages=body.packages or [],
        hardening_checks=body.hardening_checks or [],
    )
```

- [ ] **Step 5: Verify the module imports cleanly**

Run: `cd server-api && python3 -c "import ast; [ast.parse(open(f).read()) for f in ['app/models/models.py','app/main.py','app/schemas/schemas.py','app/api/routes/hygiene.py']]; print('OK')"`
Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add server-api/app/models/models.py server-api/app/main.py server-api/app/schemas/schemas.py server-api/app/api/routes/hygiene.py
git commit -m "feat(server-api): persist agent-reported OS hardening checks"
```

---

### Task 7: Upgrade Compliance Manager checks to use hardening_checks (Python)

**Files:**
- Modify: `server-api/app/services/compliance.py`

**Interfaces:**
- Consumes: `HygieneSnapshot.hardening_checks` from Task 6.
- Produces: two new check keys `ssh_hardening`, `kernel_hardening` registered in `CHECKS`; upgrades `local_account_hygiene` and `open_ports_hardening` in place (same keys, same function names, richer logic with a fallback path).

- [ ] **Step 1: Add the aggregation helper**

In `server-api/app/services/compliance.py`, add this function right after `_check_open_ports_hardening` (keep it near the checks that will use it):

```python
def _aggregate_hardening_category(snap: HygieneSnapshot, category: str) -> CheckResult | None:
    """Aggregate all agent-reported hardening checks in one category into a
    single control status. Returns None if this host hasn't reported any
    hardening data yet for this category — callers fall back to older,
    shallower logic so hosts on a not-yet-upgraded agent don't regress."""
    checks = [c for c in (snap.hardening_checks or []) if c.get("category") == category]
    if not checks:
        return None
    applicable = [c for c in checks if c.get("status") != "not_applicable"]
    if not applicable:
        return {"status": "not_automated", "evidence": f"All {len(checks)} {category} check(s) reported not_applicable on this host."}
    failed = [c for c in applicable if c.get("status") in ("fail", "error")]
    passed = [c for c in applicable if c.get("status") == "pass"]
    if not failed:
        return {"status": "met", "evidence": f"All {len(passed)} applicable {category} hardening check(s) pass."}
    failed_titles = ", ".join(c.get("title", c.get("id", "?")) for c in failed)
    if passed:
        return {"status": "partial", "evidence": f"{len(passed)}/{len(applicable)} {category} check(s) pass. Failing: {failed_titles}."}
    return {"status": "gap", "evidence": f"All {len(applicable)} {category} hardening check(s) fail: {failed_titles}."}
```

- [ ] **Step 2: Upgrade `_check_local_account_hygiene` with a hardening-data path**

Find the current function:

```python
async def _check_local_account_hygiene(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap or snap.users is None:
        return {"status": "not_automated", "evidence": "No local account data collected yet from this host."}
    users = snap.users
    root_uid0 = [u.get("name") for u in users if u.get("uid") == 0]
    extra_root = [n for n in root_uid0 if n != "root"]
    interactive = [u for u in users if u.get("shell", "") not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "")]
    if extra_root:
        return {"status": "gap", "evidence": f"Non-root account(s) with UID 0 (root-equivalent): {', '.join(extra_root)}."}
    return {"status": "met", "evidence": f"{len(interactive)} local account(s) with an interactive shell; no unauthorized UID-0 accounts."}
```

Replace with:

```python
async def _check_local_account_hygiene(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No local account data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "account")
    if aggregated is not None:
        return aggregated
    # Fall back to the shallow UID-0 check for hosts on an older agent
    # version that hasn't reported hardening_checks yet.
    if snap.users is None:
        return {"status": "not_automated", "evidence": "No local account data collected yet from this host."}
    users = snap.users
    root_uid0 = [u.get("name") for u in users if u.get("uid") == 0]
    extra_root = [n for n in root_uid0 if n != "root"]
    interactive = [u for u in users if u.get("shell", "") not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "")]
    if extra_root:
        return {"status": "gap", "evidence": f"Non-root account(s) with UID 0 (root-equivalent): {', '.join(extra_root)}."}
    return {"status": "met", "evidence": f"{len(interactive)} local account(s) with an interactive shell; no unauthorized UID-0 accounts."}
```

- [ ] **Step 3: Upgrade `_check_open_ports_hardening` with a hardening-data path**

Find the current function:

```python
async def _check_open_ports_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap or snap.open_ports is None:
        return {"status": "not_automated", "evidence": "No open-port data collected yet from this host."}
    found = []
    for p in snap.open_ports:
        port = p.get("port") if isinstance(p, dict) else None
        if port in _INSECURE_PORTS and (p.get("state") or "").lower() in ("listen", "listening", "open"):
            found.append(f"{port}/{_INSECURE_PORTS[port]}")
    if found:
        return {"status": "gap", "evidence": f"Legacy/insecure service(s) listening: {', '.join(found)}."}
    return {"status": "met", "evidence": f"No legacy/insecure services (FTP, Telnet, r-commands, X11) found among {len(snap.open_ports)} open port(s)."}
```

Replace with:

```python
async def _check_open_ports_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No open-port data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "network")
    if aggregated is not None:
        return aggregated
    if snap.open_ports is None:
        return {"status": "not_automated", "evidence": "No open-port data collected yet from this host."}
    found = []
    for p in snap.open_ports:
        port = p.get("port") if isinstance(p, dict) else None
        if port in _INSECURE_PORTS and (p.get("state") or "").lower() in ("listen", "listening", "open"):
            found.append(f"{port}/{_INSECURE_PORTS[port]}")
    if found:
        return {"status": "gap", "evidence": f"Legacy/insecure service(s) listening: {', '.join(found)}."}
    return {"status": "met", "evidence": f"No legacy/insecure services (FTP, Telnet, r-commands, X11) found among {len(snap.open_ports)} open port(s)."}
```

- [ ] **Step 4: Add the two new checks**

Add after `_check_open_ports_hardening` (or right after the helper from Step 1):

```python
async def _check_ssh_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No SSH hardening data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "ssh")
    if aggregated is not None:
        return aggregated
    return {"status": "not_automated", "evidence": "This host's agent hasn't reported SSH hardening checks yet (requires an agent update)."}


async def _check_kernel_hardening(db: AsyncSession, agent_id: str) -> CheckResult:
    snap = await _latest_snapshot(db, agent_id)
    if not snap:
        return {"status": "not_automated", "evidence": "No kernel hardening data collected yet from this host."}
    aggregated = _aggregate_hardening_category(snap, "kernel")
    if aggregated is not None:
        return aggregated
    return {"status": "not_automated", "evidence": "This host's agent hasn't reported kernel hardening checks yet (requires an agent update)."}
```

- [ ] **Step 5: Register the new checks**

Find:

```python
CHECKS: dict[str, Callable[[AsyncSession, str], Awaitable[CheckResult]]] = {
    "hygiene_posture": _check_hygiene_posture,
    "open_ports_hardening": _check_open_ports_hardening,
    "disk_capacity": _check_disk_capacity,
    "agent_monitoring_health": _check_agent_monitoring_health,
    "file_integrity_monitoring": _check_file_integrity_monitoring,
    "local_account_hygiene": _check_local_account_hygiene,
}
```

Replace with:

```python
CHECKS: dict[str, Callable[[AsyncSession, str], Awaitable[CheckResult]]] = {
    "hygiene_posture": _check_hygiene_posture,
    "open_ports_hardening": _check_open_ports_hardening,
    "disk_capacity": _check_disk_capacity,
    "agent_monitoring_health": _check_agent_monitoring_health,
    "file_integrity_monitoring": _check_file_integrity_monitoring,
    "local_account_hygiene": _check_local_account_hygiene,
    "ssh_hardening": _check_ssh_hardening,
    "kernel_hardening": _check_kernel_hardening,
}
```

- [ ] **Step 6: Add the two new controls to each framework**

In the `FRAMEWORKS` dict, for `"iso27001"`, find the last control in its `"controls"` list:

```python
            {"id": "A.9.2.5", "title": "Review of local user access rights", "check": "local_account_hygiene"},
        ],
    },
```

Replace with:

```python
            {"id": "A.9.2.5", "title": "Review of local user access rights", "check": "local_account_hygiene"},
            {"id": "A.8.20", "title": "SSH remote access hardening", "check": "ssh_hardening"},
            {"id": "A.8.9", "title": "Configuration hardening (kernel/filesystem)", "check": "kernel_hardening"},
        ],
    },
```

For `"pci_dss"`, find:

```python
            {"id": "Req 7.2", "title": "Unique accounts, no shared/root-equivalent access", "check": "local_account_hygiene"},
        ],
    },
```

Replace with:

```python
            {"id": "Req 7.2", "title": "Unique accounts, no shared/root-equivalent access", "check": "local_account_hygiene"},
            {"id": "Req 2.2.7", "title": "Secure remote administrative access (SSH hardening)", "check": "ssh_hardening"},
            {"id": "Req 2.2", "title": "System configuration hardening", "check": "kernel_hardening"},
        ],
    },
```

For `"soc2"`, find:

```python
            {"id": "CC6.2", "title": "Periodic review of provisioned local accounts", "check": "local_account_hygiene"},
        ],
    },
```

Replace with:

```python
            {"id": "CC6.2", "title": "Periodic review of provisioned local accounts", "check": "local_account_hygiene"},
            {"id": "CC6.1b", "title": "Secure remote access configuration", "check": "ssh_hardening"},
            {"id": "CC6.8", "title": "Prevents/detects unauthorized software and configuration changes", "check": "kernel_hardening"},
        ],
    },
```

- [ ] **Step 7: Verify the module imports cleanly**

Run: `cd server-api && python3 -c "import ast; ast.parse(open('app/services/compliance.py').read()); print('OK')"`
Expected: `OK`

- [ ] **Step 8: Commit**

```bash
git add server-api/app/services/compliance.py
git commit -m "feat(server-api): upgrade Compliance Manager with OS hardening controls"
```

---

### Task 8: Local end-to-end verification

**Files:** none (verification only)

**Interfaces:** none — this task proves Tasks 1-7 work together.

- [ ] **Step 1: Run the full Go test suite for the agent**

Run: `cd agent && go build ./... && go test ./... -v 2>&1 | tail -60`
Expected: all packages build and all tests pass, including the ~20 new tests in `internal/hardening`.

- [ ] **Step 2: Rebuild the local dev stack**

Run: `cd /home/wonka/Documents/ADSIEM && docker compose build server-api package-builder && docker compose up -d --force-recreate server-api package-builder`
Expected: both build and start; `package-builder` exits 0 after producing `siem-agent-1.2.0-1.x86_64.rpm` (or the current `AGENT_VERSION`) with the new hardening code baked in.

- [ ] **Step 3: Confirm the new column exists**

Run: `docker compose exec -T postgres psql -U soc -d soc_platform -c "\d hygiene_snapshots" | grep hardening_checks`
Expected: one line showing `hardening_checks | jsonb`.

- [ ] **Step 4: Install the freshly-built package on a real Linux target and confirm the field populates**

If a spare local VM/container running the existing `agent-demo` or `demo-web01` test agent is available, upgrade it the same way WAF-SERVER was upgraded earlier this session (`rpm -Uvh` the new package, restart the `siem-agent` service), then query that agent's latest hygiene snapshot via the API and confirm `hardening_checks` is a non-empty list of 16 entries with real `pass`/`fail`/`not_applicable` statuses (not all `error`).

If no spare Linux target is available locally, skip straight to Task 9's production rollout, which performs this same verification against WAF-SERVER.

- [ ] **Step 5: Confirm the Compliance Manager page shows the new controls**

Log into the local dashboard, navigate to `/compliance`, select the upgraded endpoint, and confirm both "SSH remote access hardening" and "Configuration hardening (kernel/filesystem)" controls now appear (for whichever framework tab is open) with real evidence text — not `NO DATA` for every check.

---

### Task 9: Production deployment

**Files:** none (deployment only)

**Interfaces:** none.

- [ ] **Step 1: Copy the changed files to the production host**

Copy every file touched in Tasks 1-7 (`agent/internal/hardening/*.go`, `agent/internal/hygiene/types.go`, `agent/internal/hygiene/collector.go`, `server-api/app/models/models.py`, `server-api/app/main.py`, `server-api/app/schemas/schemas.py`, `server-api/app/api/routes/hygiene.py`, `server-api/app/services/compliance.py`) into place under `/opt/ADSIEM` on `103.204.15.99`, the same way every other file this session was deployed (scp to `/tmp`, then `su -c "cp ... && chown solusi247:solusi247 ..."`).

- [ ] **Step 2: Rebuild server-api, package-builder, and dashboard on production**

```bash
cd /opt/ADSIEM
docker compose -f docker-compose.yml -f docker-compose.prod.yml build --no-cache package-builder
docker compose -f docker-compose.yml -f docker-compose.prod.yml build server-api
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate package-builder
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d server-api
```

Expected: `server-api-1` and `server-api-2` both reach `healthy` quickly (the transaction-leak fix from earlier this session means no lock-contention hang); `package-builder` exits 0 having produced a fresh RPM with a version bump (e.g. `1.3.0`) so `rpm -Uvh` on the target host performs a real upgrade, not a same-version no-op.

- [ ] **Step 3: Extract the new RPM and upgrade WAF-SERVER**

Pull the new RPM out of the `agent_packages` docker volume (same `docker run --rm -v siem-platform_agent_packages:/output ...` pattern used earlier this session), relay it to `103.204.15.6` via the local machine, then:

```bash
rpm -Uvh /tmp/siem-agent-<new-version>.rpm
systemctl restart siem-agent
journalctl -u siem-agent --no-pager -n 20
```

Expected: clean restart, all 11 log tailers resume, no panics in the journal.

- [ ] **Step 4: Verify the hardening data actually arrives from production**

Wait for one hygiene-collection cycle, then query `GET /api/compliance/endpoints/{waf-server-agent-id}/frameworks/iso27001` (same login + curl pattern used throughout this session) and confirm `ssh_hardening` and `kernel_hardening` no longer report `not_automated`, and their evidence text reflects WAF-SERVER's real SSH/kernel configuration.

- [ ] **Step 5: Verify visually on the live dashboard**

Using the established temp-plain-http.yml swap (to bypass the self-signed cert for the headless browser), log into `http://103.204.15.99/compliance`, select the WAF-SERVER endpoint, and screenshot each framework tab showing the two new controls with real data. Restore `nginx.prod.conf` immediately afterward.

- [ ] **Step 6: Update CHANGELOG.md and docs/IMPLEMENTATION_STATUS.md**

Add an entry describing this feature (OS-level hardening checks, the 16 checks by category, the fallback behavior for older agents), following this repo's existing changelog style — a paragraph naming files touched, what was verified, and any known limitations (Linux-only; `checkFirewallActive` has no deterministic unit test since it shells out to real system tools).
