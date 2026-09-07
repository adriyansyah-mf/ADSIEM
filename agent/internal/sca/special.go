package sca

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Three checks don't fit the file/command/mount/sshd DSL cleanly enough to
// express as regex rules without either losing an important status
// distinction or requiring per-line structured parsing the DSL has no
// primitive for:
//
//   - no_empty_passwords: needs StatusError (not fail/skip) specifically
//     for "file exists but is unreadable" — a real, actionable difference
//     (non-root agent install) from "file doesn't exist" that folding
//     through a generic command/regex rule would erase.
//   - no_duplicate_root_uid: needs a uniqueness count across /etc/passwd
//     rows, not a single regex match.
//   - no_legacy_services: tests the open-port list the hygiene collector
//     already gathered, not anything on the filesystem or in a command's
//     output — there's nothing on the host itself to point a file/command
//     rule at.
//
// A policy references one of these by name via PolicyCheck.Special; all
// other metadata (title, rationale, remediation, compliance mapping) still
// comes from the policy file like every other check.
const (
	SpecialNoEmptyPasswords   = "no_empty_passwords"
	SpecialNoDuplicateRootUID = "no_duplicate_root_uid"
	SpecialNoLegacyServices   = "no_legacy_services"
)

var insecurePorts = map[int]string{
	21:   "FTP (unencrypted)",
	23:   "Telnet",
	512:  "rexec",
	513:  "rlogin",
	514:  "rsh",
	6000: "X11",
}

func evalSpecial(name string, ports []PortInfo) (Status, string) {
	switch name {
	case SpecialNoEmptyPasswords:
		return evalNoEmptyPasswords("/etc/shadow")
	case SpecialNoDuplicateRootUID:
		return evalNoDuplicateRootUID("/etc/passwd")
	case SpecialNoLegacyServices:
		return evalNoLegacyServices(ports)
	}
	return StatusError, "unknown special check: " + name
}

func evalNoEmptyPasswords(path string) (Status, string) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return StatusNotApplicable, "no shadow file on this host"
		}
		return StatusError, "cannot read shadow file: " + err.Error()
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
		return StatusFail, "empty password field for: " + strings.Join(empty, ", ")
	}
	return StatusPass, "no accounts with an empty password field"
}

func evalNoDuplicateRootUID(path string) (Status, string) {
	f, err := os.Open(path)
	if err != nil {
		return StatusNotApplicable, "no passwd file on this host"
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
		return StatusFail, "UID 0 account(s) besides root: " + strings.Join(extra, ", ")
	}
	return StatusPass, "only root has UID 0"
}

func evalNoLegacyServices(ports []PortInfo) (Status, string) {
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
		return StatusFail, "listening: " + strings.Join(found, ", ")
	}
	return StatusPass, "no legacy/insecure services found among " + strconv.Itoa(len(ports)) + " open port(s)"
}
