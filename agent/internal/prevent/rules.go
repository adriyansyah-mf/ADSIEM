// Package prevent stops (or, in detect mode, reports) program execution
// that matches the server's execution rules, before the program runs.
// On Linux the BPF LSM engine decides path, directory and parent rules in
// the kernel; the fanotify engine decides hash rules, and everything when
// the kernel has no BPF LSM.
package prevent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/siem-platform/agent/internal/malhash"
	"github.com/siem-platform/agent/internal/policy"
)

// Rule types and actions as the server sends them.
const (
	TypeHash   = "hash"   // Value: SHA-256 of the executable
	TypePath   = "path"   // Value: absolute path of the executable
	TypeDir    = "dir"    // Value: directory; anything below it
	TypeParent = "parent" // Parent: parent basenames, Value: child basenames (comma separated)
	// TypeKnownMalware is not a server rule: a hash in the known-malware set
	// (internal/malhash) matched; Name is its label.
	TypeKnownMalware = "known_malware"

	ActionDetect = "detect"
	ActionBlock  = "block"
)

const (
	maxRules       = 1024
	maxParentRules = 64
	nameLen        = 32
)

// Rule is an execution rule from the server.
type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	RuleType string `json:"rule_type"`
	Value    string `json:"value"`
	Parent   string `json:"parent"`
	Action   string `json:"action"`
}

// compiled is a rule ready for the engines; index is its position in
// Policy.Rules and the id the kernel reports.
type compiled struct {
	Rule
	index    int
	block    bool
	parents  []string
	children []string
}

// Policy is a validated rule set.
type Policy struct {
	Rules   []*compiled
	hashes  map[string]*compiled
	paths   map[string]*compiled
	dirs    []*compiled
	parents []*compiled

	// the known-malware set (checked after hash rules), the file it is saved
	// in (the fanotify helper loads it from there) and the guard's protected
	// hashes, which a known-malware match never blocks
	malware     *malhash.Set
	malwareFile string
	// group policy: off stops everything; exclusions (prevention / malware scope)
	off         bool
	exclusions  []policy.Exclusion
	guardHashes map[string]string
}

// withMalware returns a copy of p that also checks the known-malware set.
func (p *Policy) withMalware(set *malhash.Set, file string) *Policy {
	q := *p
	q.malware, q.malwareFile = set, file
	return &q
}

// checksMalware reports whether execs are checked against the known-malware set.
func (p *Policy) checksMalware() bool { return p.malware.Active() }

// active reports whether there is anything to decide.
func (p *Policy) active() bool { return !p.off && (len(p.Rules) > 0 || p.checksMalware()) }

// withGate returns a copy of p switched off (the group policy turned
// prevention off) or with the exclusions of the prevention and malware
// scopes (only rules decided in user space honour them: hash rules,
// known-malware, and everything where fanotify decides).
func (p *Policy) withGate(off bool, exclusions []policy.Exclusion) *Policy {
	q := *p
	q.off, q.exclusions = off, exclusions
	return &q
}

// malwareRule is what a known-malware match reports: index -1, blocking
// when the server says block and the file is not one the guard protects.
func (p *Policy) malwareRule(label, sha string) *compiled {
	action := ActionDetect
	block := p.malware.Block() && p.guardHashes[sha] == ""
	if block {
		action = ActionBlock
	}
	if label == "" {
		label = "unknown"
	}
	return &compiled{Rule: Rule{ID: sha, Name: label, RuleType: TypeKnownMalware, Value: sha, Action: action},
		index: -1, block: block}
}

func splitNames(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, filepath.Base(n))
		}
	}
	return out
}

// protected executables are never blocked, whatever the rules say:
// blocking them takes the host (or the agent) down.
var protectedPaths = []string{
	"/sbin/init", "/usr/sbin/init", "/lib/systemd/systemd", "/usr/lib/systemd/systemd",
	"/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/dash", "/usr/bin/dash",
	"/usr/sbin/sshd", "/usr/bin/sudo", "/usr/bin/login", "/usr/sbin/nft", "/usr/sbin/iptables",
}

// foldCase: Windows paths and file names are case-insensitive, so rule
// values and the executions they are matched against are lower-cased there.
// Linux keeps exact case (the BPF LSM engine loads these values as they are).
var foldCase = runtime.GOOS == "windows"

func fold(s string) string {
	if foldCase {
		return strings.ToLower(s)
	}
	return s
}

// windowsProtected are never blocked on Windows: the critical processes
// (terminating one crashes or locks up the host), the shell and PowerShell
// an administrator recovers with, and Explorer. They are taken from the
// system directory, so a copy elsewhere with the same name is not protected.
func windowsProtected() []string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	sys := filepath.Join(root, "System32")
	var out []string
	for _, n := range []string{"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
		"lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "conhost.exe",
		"cmd.exe", "WindowsPowerShell\\v1.0\\powershell.exe"} {
		out = append(out, filepath.Join(sys, n))
	}
	return append(out, filepath.Join(root, "explorer.exe"))
}

// guard explains why a block rule must not be enforced, or returns "".
type guard struct {
	paths  []string
	hashes map[string]string
}

func newGuard() *guard {
	g := &guard{hashes: map[string]string{}}
	paths := append([]string{}, protectedPaths...)
	if runtime.GOOS == "windows" {
		paths = windowsProtected()
	}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, exe)
	}
	for _, p := range paths {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		g.paths = append(g.paths, fold(real))
		if h, err := hashFile(real, 256<<20); err == nil {
			g.hashes[h] = real
		}
	}
	return g
}

func under(path, dir string) bool {
	sep := string(filepath.Separator)
	dir = strings.TrimSuffix(dir, sep)
	return path == dir || strings.HasPrefix(path, dir+sep) || dir == ""
}

func (g *guard) refuse(c *compiled) string {
	switch c.RuleType {
	case TypeHash:
		if p, ok := g.hashes[c.Value]; ok {
			return "the hash is " + p
		}
	case TypePath, TypeDir:
		target := c.Value
		if real, err := filepath.EvalSymlinks(target); err == nil {
			target = fold(real)
		}
		for _, p := range g.paths {
			if (c.RuleType == TypePath && p == target) || (c.RuleType == TypeDir && under(p, target)) {
				return "it covers " + p
			}
		}
	}
	return ""
}

// Compile validates rules. Invalid rules are left out and reported; a
// block rule the guard refuses is kept in detect mode.
func Compile(rules []Rule) (*Policy, []error) {
	return compileWith(rules, newGuard())
}

func compileWith(rules []Rule, g *guard) (*Policy, []error) {
	p := &Policy{hashes: map[string]*compiled{}, paths: map[string]*compiled{}, guardHashes: g.hashes}
	var errs []error
	for _, r := range rules {
		c := &compiled{Rule: r, block: r.Action == ActionBlock}
		if r.Action != ActionBlock && r.Action != ActionDetect {
			errs = append(errs, fmt.Errorf("rule %q: unknown action %q", r.Name, r.Action))
			continue
		}
		switch r.RuleType {
		case TypeHash:
			c.Value = strings.ToLower(strings.TrimSpace(r.Value))
			if b, err := hex.DecodeString(c.Value); err != nil || len(b) != sha256.Size {
				errs = append(errs, fmt.Errorf("rule %q: not a SHA-256: %q", r.Name, r.Value))
				continue
			}
		case TypePath, TypeDir:
			if !filepath.IsAbs(r.Value) {
				// also a path for the other OS (C:\... on Linux, /usr/... on Windows)
				errs = append(errs, fmt.Errorf("rule %q: %s must be an absolute path on this system", r.Name, r.RuleType))
				continue
			}
			c.Value = fold(filepath.Clean(r.Value))
		case TypeParent:
			c.parents, c.children = splitNames(fold(r.Parent)), splitNames(fold(r.Value))
			if len(c.parents) == 0 || len(c.children) == 0 {
				errs = append(errs, fmt.Errorf("rule %q: parent rules need parent and child names", r.Name))
				continue
			}
			if len(p.parents) == maxParentRules {
				errs = append(errs, fmt.Errorf("rule %q: more than %d parent rules", r.Name, maxParentRules))
				continue
			}
		default:
			errs = append(errs, fmt.Errorf("rule %q: unknown type %q", r.Name, r.RuleType))
			continue
		}
		if len(p.Rules) == maxRules {
			errs = append(errs, fmt.Errorf("more than %d rules; the rest are ignored", maxRules))
			break
		}
		if c.block {
			if why := g.refuse(c); why != "" {
				slog.Warn("prevent: block rule kept in detect mode", "rule", r.Name, "reason", why)
				errs = append(errs, fmt.Errorf("rule %q: not blocking: %s", r.Name, why))
				c.block = false
			}
		}
		c.index = len(p.Rules)
		p.Rules = append(p.Rules, c)
		switch r.RuleType {
		case TypeHash:
			p.hashes[c.Value] = c
		case TypePath:
			p.paths[c.Value] = c
		case TypeDir:
			p.dirs = append(p.dirs, c)
		case TypeParent:
			p.parents = append(p.parents, c)
		}
	}
	return p, errs
}

// HasHashRules reports whether only the fanotify engine can decide some rules.
func (p *Policy) HasHashRules() bool { return len(p.hashes) > 0 }

// Exec is one execution attempt as the fanotify engine sees it.
type Exec struct {
	Path   string                // executable (or script) being run
	Parent string                // image of the process calling exec
	Hash   func() (string, bool) // SHA-256 of the file, computed on demand
}

// Match returns the first rule matching e: path, then directory, then
// parent, then hash (the only one that reads the file). kernelDecides
// leaves out the rule types the BPF LSM engine already enforces.
func (p *Policy) Match(e Exec, kernelDecides bool) *compiled {
	if p.off {
		return nil
	}
	var sum string
	if h := e.Hash; h != nil {
		e.Hash = func() (string, bool) {
			v, ok := h()
			if ok {
				sum = v
			}
			return v, ok
		}
	}
	c := p.match(e, kernelDecides)
	if c == nil || len(p.exclusions) == 0 {
		return c
	}
	scope := policy.ScopePrevention
	if c.RuleType == TypeKnownMalware {
		scope = policy.ScopeMalware
	}
	if (policy.Settings{Exclusions: p.exclusions}).Excluded(scope, policy.Match{Image: e.Path, Path: e.Path, SHA256: sum}) {
		return nil
	}
	return c
}

func (p *Policy) match(e Exec, kernelDecides bool) *compiled {
	e.Path, e.Parent = fold(e.Path), fold(e.Parent)
	if !kernelDecides {
		if c := p.paths[e.Path]; c != nil {
			return c
		}
		for _, c := range p.dirs {
			if under(e.Path, c.Value) && e.Path != c.Value {
				return c
			}
		}
		child, parent := filepath.Base(e.Path), filepath.Base(e.Parent)
		for _, c := range p.parents {
			if contains(c.children, child) && contains(c.parents, parent) {
				return c
			}
		}
	}
	if (len(p.hashes) > 0 || p.checksMalware()) && e.Hash != nil {
		if h, ok := e.Hash(); ok {
			if c := p.hashes[h]; c != nil {
				return c
			}
			if label, known := p.malware.Lookup(h); known {
				return p.malwareRule(label, h)
			}
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func hashFile(path string, max int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return hashReader(f, max)
}

func hashReader(r io.Reader, max int64) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, max+1))
	if err != nil {
		return "", err
	}
	if n > max {
		return "", fmt.Errorf("larger than %d bytes", max)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
