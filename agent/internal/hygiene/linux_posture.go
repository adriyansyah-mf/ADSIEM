package hygiene

// Linux security posture. The checks are plain functions over what the host
// exposes (files, command output) so they are tested on any OS; the Linux
// collector passes the real host (collector.go). Severities match the Windows
// checks for the same risk (windows_posture.go): no host firewall, remote
// login that takes a password for an admin, privilege without a password,
// pending reboot, no automatic updates, no mandatory access control.

import (
	"path/filepath"
	"sort"
	"strings"
)

// linuxHost is what the posture checks read.
type linuxHost struct {
	readFile func(path string) (string, error)
	glob     func(pattern string) []string
	exists   func(path string) bool
	// run executes a program and returns its output; err when it is missing
	// or failed.
	run func(name string, args ...string) (string, error)
}

func linuxPosture(h linuxHost, r *Report) []Issue {
	var issues []Issue
	add := func(sev, cat, msg string) { issues = append(issues, Issue{sev, cat, msg}) }

	if !linuxFirewallActive(h) {
		add("high", "firewall", "No host firewall filters inbound traffic (ufw, firewalld, nftables and iptables all accept by default)")
	}

	if root, pass, ok := sshdSettings(h); ok {
		switch {
		case root == "yes" && pass == "yes":
			add("high", "ssh", "SSH allows root to log in with a password (PermitRootLogin yes, PasswordAuthentication yes)")
		case root == "yes":
			add("medium", "ssh", "SSH allows root to log in (PermitRootLogin yes)")
		}
		if pass == "yes" && root != "yes" {
			add("medium", "ssh", "SSH accepts passwords (PasswordAuthentication yes): brute force can succeed")
		}
	}

	if who := sudoNopasswd(h); len(who) > 0 {
		add("medium", "privilege", "sudo without a password for: "+strings.Join(who, ", "))
	}

	passwd, _ := h.readFile("/etc/passwd")
	if extra := extraUID0(passwd); len(extra) > 0 {
		add("critical", "user", "Accounts other than root with UID 0: "+strings.Join(extra, ", "))
	}
	if shadow, err := h.readFile("/etc/shadow"); err == nil {
		if empty := emptyPasswords(shadow, passwd); len(empty) > 0 {
			add("high", "user", "Accounts that can log in without a password: "+strings.Join(empty, ", "))
		}
	}

	if h.exists("/var/run/reboot-required") || h.exists("/run/reboot-required") {
		msg := "A reboot is pending: installed updates (often the kernel) are not running yet"
		if pkgs, err := h.readFile("/var/run/reboot-required.pkgs"); err == nil {
			if list := uniq(strings.Fields(pkgs)); len(list) > 0 {
				msg += " (" + strings.Join(firstN(list, 5), ", ") + ")"
			}
		}
		add("medium", "patch", msg)
	}

	if auto, known := linuxAutoUpdates(h, r); known && !auto {
		add("medium", "patch", "Automatic security updates are off (unattended-upgrades / dnf-automatic)")
	}

	if !linuxMACEnforcing(h) {
		add("low", "protection", "No mandatory access control enforcing (AppArmor or SELinux)")
	}
	return issues
}

// linuxFirewallActive: ufw or firewalld on, or an nftables/iptables input
// chain that drops by default. The agent's own nftables tables (siem_*:
// isolation, IP IoC blocking) accept by default and do not count.
func linuxFirewallActive(h linuxHost) bool {
	if conf, err := h.readFile("/etc/ufw/ufw.conf"); err == nil && confValue(conf, "ENABLED") == "yes" {
		return true
	}
	if out, err := h.run("systemctl", "is-active", "firewalld"); err == nil && strings.TrimSpace(out) == "active" {
		return true
	}
	if out, err := h.run("nft", "list", "ruleset"); err == nil && nftInputDrops(out) {
		return true
	}
	if out, err := h.run("iptables", "-S", "INPUT"); err == nil && iptablesInputDrops(out) {
		return true
	}
	return false
}

func confValue(conf, key string) string {
	for _, line := range strings.Split(conf, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// nftInputDrops reports a base chain on the input hook whose policy is drop,
// outside the agent's own siem_* tables.
func nftInputDrops(ruleset string) bool {
	table := ""
	for _, line := range strings.Split(ruleset, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "table" {
			table = f[2]
			continue
		}
		if strings.HasPrefix(table, "siem_") {
			continue
		}
		l := strings.TrimSpace(line)
		if strings.Contains(l, "hook input") && strings.Contains(l, "policy drop") {
			return true
		}
	}
	return false
}

func iptablesInputDrops(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "-P" && f[1] == "INPUT" && (f[2] == "DROP" || f[2] == "REJECT") {
			return true
		}
		// ufw managed through iptables without ufw.conf
		if len(f) >= 4 && f[0] == "-A" && f[1] == "INPUT" && strings.HasPrefix(f[3], "ufw-") {
			return true
		}
	}
	return false
}

// sshdSettings returns PermitRootLogin and PasswordAuthentication as sshd
// applies them: `sshd -T` (the effective configuration, Includes and
// defaults resolved), else the config files with sshd's first-value-wins
// rule and its defaults. ok is false when sshd is not installed.
func sshdSettings(h linuxHost) (root, pass string, ok bool) {
	for _, bin := range []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"} {
		if !h.exists(bin) {
			continue
		}
		if out, err := h.run(bin, "-T"); err == nil {
			root, pass = sshdKeyword(out, "permitrootlogin"), sshdKeyword(out, "passwordauthentication")
			if root != "" || pass != "" {
				return root, pass, true
			}
		}
		root, pass = sshdFromFiles(h)
		return root, pass, true
	}
	return "", "", false
}

func sshdKeyword(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], key) {
			return strings.ToLower(f[1])
		}
	}
	return ""
}

// sshdFromFiles reads sshd_config in order, Include files where they are
// included; the first value of a keyword wins (outside Match blocks).
func sshdFromFiles(h linuxHost) (root, pass string) {
	var lines []string
	var load func(path string, depth int)
	load = func(path string, depth int) {
		text, err := h.readFile(path)
		if err != nil || depth > 4 {
			return
		}
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && strings.EqualFold(f[0], "include") {
				for _, pattern := range f[1:] {
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join("/etc/ssh", pattern)
					}
					matches := h.glob(pattern)
					sort.Strings(matches)
					for _, m := range matches {
						load(m, depth+1)
					}
				}
				continue
			}
			lines = append(lines, line)
		}
	}
	load("/etc/ssh/sshd_config", 0)
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if strings.EqualFold(f[0], "match") {
			break // conditional blocks do not set the defaults
		}
		switch strings.ToLower(f[0]) {
		case "permitrootlogin":
			if root == "" {
				root = strings.ToLower(f[1])
			}
		case "passwordauthentication":
			if pass == "" {
				pass = strings.ToLower(f[1])
			}
		}
	}
	if root == "" {
		root = "prohibit-password"
	}
	if pass == "" {
		pass = "yes"
	}
	return root, pass
}

// sudoNopasswd lists who sudoers lets run commands without a password.
// sudo skips files in sudoers.d whose names end in ~ or contain a dot.
func sudoNopasswd(h linuxHost) []string {
	files := []string{"/etc/sudoers"}
	for _, f := range h.glob("/etc/sudoers.d/*") {
		base := filepath.Base(f)
		if strings.HasSuffix(base, "~") || strings.Contains(base, ".") {
			continue
		}
		files = append(files, f)
	}
	seen := map[string]bool{}
	var who []string
	for _, f := range files {
		text, err := h.readFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "Defaults") || !strings.Contains(l, "NOPASSWD") {
				continue
			}
			if p := strings.Fields(l)[0]; !seen[p] {
				seen[p] = true
				who = append(who, p)
			}
		}
	}
	return who
}

func extraUID0(passwd string) []string {
	var out []string
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && f[2] == "0" && f[0] != "root" {
			out = append(out, f[0])
		}
	}
	return out
}

// emptyPasswords: shadow entries with an empty password field, for accounts
// whose shell allows a login.
func emptyPasswords(shadow, passwd string) []string {
	shells := map[string]string{}
	for _, line := range strings.Split(passwd, "\n") {
		if f := strings.Split(line, ":"); len(f) >= 7 {
			shells[f[0]] = f[6]
		}
	}
	var out []string
	for _, line := range strings.Split(shadow, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 2 || f[0] == "" || f[1] != "" {
			continue
		}
		if sh := shells[f[0]]; sh == "" || strings.HasSuffix(sh, "nologin") || strings.HasSuffix(sh, "false") {
			continue
		}
		out = append(out, f[0])
	}
	return out
}

// linuxAutoUpdates: known is false where neither the Debian nor the RHEL
// mechanism applies (no opinion on other distributions).
func linuxAutoUpdates(h linuxHost, r *Report) (on, known bool) {
	switch {
	case h.exists("/etc/apt/apt.conf.d"):
		for _, f := range h.glob("/etc/apt/apt.conf.d/*") {
			text, err := h.readFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(text, "\n") {
				l := strings.TrimSpace(line)
				if strings.HasPrefix(l, "APT::Periodic::Unattended-Upgrade") && strings.Contains(l, `"1"`) {
					return hasPackage(r, "unattended-upgrades"), true
				}
			}
		}
		return false, true
	case h.exists("/etc/dnf"):
		for _, t := range []string{"dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer"} {
			if h.exists("/etc/systemd/system/timers.target.wants/" + t) {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}

func hasPackage(r *Report, name string) bool {
	if r == nil || len(r.Packages) == 0 {
		return true // inventory unavailable: trust the configuration
	}
	for _, p := range r.Packages {
		if p.Name == name {
			return true
		}
	}
	return false
}

func linuxMACEnforcing(h linuxHost) bool {
	if v, err := h.readFile("/sys/module/apparmor/parameters/enabled"); err == nil && strings.TrimSpace(v) == "Y" {
		return true
	}
	if v, err := h.readFile("/sys/fs/selinux/enforce"); err == nil && strings.TrimSpace(v) == "1" {
		return true
	}
	return false
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	out := s[:0:0]
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
