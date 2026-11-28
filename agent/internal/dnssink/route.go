package dnssink

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Router sends the blocked domains' names to the resolver at the OS level.
type Router interface {
	// Apply makes the OS send names under these domains (and only those) to
	// the resolver; an empty list removes the routing.
	Apply(domains []string) error
	Remove() error
	// Prepare readies what the resolver listens on (Linux: the dummy link
	// and its address) and returns the address to listen on.
	Prepare() (addr string, err error)
}

// ErrUnavailable: this host has no way to route a namespace to a resolver
// (Linux without systemd-resolved); the hosts-file web block still applies.
var ErrUnavailable = errors.New("dnssink: no per-domain DNS routing on this host")

// Exec runs a command; replaced in tests.
type Exec func(ctx context.Context, name string, args ...string) (string, error)

func realExec(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, text)
	}
	return text, nil
}

// LinkName is the dummy link that carries the routing domains in systemd-resolved.
const LinkName = "adsiem-dns"

// LinkIP is the dummy link's address and where the resolver listens on
// Linux. systemd-resolved sends a link's queries out of that link
// (IP_UNICAST_IF), so the server must be on an address of the link itself:
// a loopback address would not be reached. Link-local /32: never routed off
// the host.
const LinkIP = "169.254.84.1"

const linkAddr = LinkIP + "/32"

// ResolvedRouter routes with systemd-resolved (Linux): the dummy link's DNS
// server is the resolver and its routing domains (~evil.com) are the blocked
// domains, so only their names are sent there. Runtime settings: a restart of
// systemd-resolved drops them, and the controller applies them again.
type ResolvedRouter struct {
	Run Exec
}

func (r ResolvedRouter) run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := r.Run
	if run == nil {
		run = realExec
	}
	return run(ctx, name, args...)
}

// available: resolvectl exists and systemd-resolved runs.
func (r ResolvedRouter) available() bool {
	if _, err := r.run("systemctl", "is-active", "--quiet", "systemd-resolved"); err != nil {
		return false
	}
	_, err := r.run("resolvectl", "--version")
	return err == nil
}

// Prepare creates the dummy link with its address (idempotent).
func (r ResolvedRouter) Prepare() (string, error) {
	if !r.available() {
		return "", ErrUnavailable
	}
	if _, err := r.run("ip", "link", "show", LinkName); err != nil {
		if _, err := r.run("ip", "link", "add", LinkName, "type", "dummy"); err != nil {
			return "", err
		}
	}
	for _, args := range [][]string{
		{"ip", "link", "set", LinkName, "up"},
		{"ip", "addr", "replace", linkAddr, "dev", LinkName},
	} {
		if _, err := r.run(args[0], args[1:]...); err != nil {
			return "", err
		}
	}
	return LinkIP + ":53", nil
}

func (r ResolvedRouter) Apply(domains []string) error {
	if len(domains) == 0 {
		return r.Remove()
	}
	if _, err := r.Prepare(); err != nil { // a restarted resolved or a removed link
		return err
	}
	if _, err := r.run("resolvectl", "dns", LinkName, LinkIP); err != nil {
		return err
	}
	routing := []string{"domain", LinkName}
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	for _, d := range sorted {
		routing = append(routing, "~"+d)
	}
	if _, err := r.run("resolvectl", routing...); err != nil {
		return err
	}
	// never the default route for other names (older systemd has no such verb)
	_, _ = r.run("resolvectl", "default-route", LinkName, "false")
	_, _ = r.run("resolvectl", "flush-caches")
	return nil
}

func (r ResolvedRouter) Remove() error {
	if _, err := r.run("ip", "link", "show", LinkName); err != nil {
		return nil // nothing of ours
	}
	_, err := r.run("ip", "link", "del", LinkName)
	_, _ = r.run("resolvectl", "flush-caches")
	return err
}

// NRPTComment marks the agent's Name Resolution Policy Table rule (Windows).
const NRPTComment = "ADSIEM DNS sinkhole"

// PSRunner runs a PowerShell script (appcontrol.PowerShell on Windows).
type PSRunner func(ctx context.Context, script string) (string, error)

// NRPTRouter routes with one NRPT rule (Windows): every blocked domain and
// its subdomains (namespaces "evil.com" and ".evil.com") go to the
// resolver. Only the agent's rule (by its comment) is ever replaced or
// removed; a company VPN's NRPT rules are left alone.
type NRPTRouter struct {
	Run PSRunner
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// NRPTScript replaces the agent's NRPT rule with one for domains (none: removed).
func NRPTScript(domains []string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("$ErrorActionPreference = 'Stop'")
	w("$c = %s", psQuote(NRPTComment))
	w("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $c } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }")
	if len(domains) > 0 {
		sorted := append([]string(nil), domains...)
		sort.Strings(sorted)
		var ns []string
		for _, d := range sorted {
			ns = append(ns, psQuote(d), psQuote("."+d))
		}
		w("$ns = @(%s)", strings.Join(ns, ", "))
		w("Add-DnsClientNrptRule -Namespace $ns -NameServers %s -Comment $c | Out-Null", psQuote(strings.Split(Addr, ":")[0]))
	}
	w("Clear-DnsClientCache")
	w("'ok'")
	return b.String()
}

func (r NRPTRouter) Apply(domains []string) error {
	if r.Run == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := r.Run(ctx, NRPTScript(domains))
	return err
}

func (r NRPTRouter) Remove() error { return r.Apply(nil) }

// Persistent: NRPT rules survive a DNS client restart and a reboot.
func (NRPTRouter) Persistent() bool { return true }

// Prepare: nothing to create; the resolver listens on the sink address.
func (r NRPTRouter) Prepare() (string, error) {
	if r.Run == nil {
		return "", ErrUnavailable
	}
	return Addr, nil
}
