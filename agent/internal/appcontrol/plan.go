// Package appcontrol turns the execution prevention block rules into a
// Windows App Control (WDAC) policy, so Windows itself refuses the program
// before it runs, like the BPF LSM does on Linux. Without it the agent can
// only stop a program right after it starts (ETW sees the start). The group
// policy's app_control picks off, audit (Windows logs what it would block in
// Microsoft-Windows-CodeIntegrity/Operational) or enforce.
//
// The policy is Windows' AllowAll example with deny rules added: everything
// runs except what the rules name, so it cannot lock a host out. Path and
// dir rules become FilePath deny rules; hash rules cannot be translated
// (WDAC matches Authenticode hashes, the rules hold file SHA-256), so a file a
// hash rule (or the known-malware set) stopped is learned and denied by its
// Authenticode hash from then on.
package appcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PolicyID is the agent's policy GUID: every apply replaces the same policy.
const PolicyID = "{5B4F2A6C-9D1E-4F3A-8C7B-2E6D1A0F9C35}"

// PolicyName is how the policy shows in CiTool --list-policies.
const PolicyName = "SIEM Agent App Control"

// Modes of the group policy's app_control.
const (
	ModeOff     = "off"
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)

// MaxLearned bounds the files learned from terminated programs.
const MaxLearned = 500

// Plan is what one policy holds.
type Plan struct {
	Mode    string   `json:"mode"`
	Paths   []string `json:"paths"`   // executables denied by path
	Dirs    []string `json:"dirs"`    // folders: anything below them is denied
	Learned []string `json:"learned"` // files denied by their Authenticode hash
	// Signers are policy fragments, one per publisher a signer block rule
	// names, each a deny at WDAC's Publisher level built once from a sample
	// file (FragmentScript): everything that publisher signed is denied.
	Signers []string `json:"signers,omitempty"`
}

var winAbs = regexp.MustCompile(`^[A-Za-z]:\\`)

// NewPlan builds the plan from the block rules (rule type, value), the
// learned files and the publisher fragments that are ready (lower-case
// publisher -> fragment file); values that are not absolute Windows paths
// are left out (Linux paths from a fleet-wide rule set). A fragment counts
// only while a signer block rule still names its publisher: turning the rule
// off lifts the publisher deny at the next reconcile.
func NewPlan(mode string, rules [][2]string, learned []string, signers map[string]string) Plan {
	p := Plan{Mode: mode}
	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		v = strings.TrimRight(strings.TrimSpace(v), `\`)
		if !winAbs.MatchString(v) || strings.ContainsAny(v, "\r\n\x00") {
			return
		}
		key := strings.ToLower(v)
		if seen[key] {
			return
		}
		seen[key] = true
		*dst = append(*dst, v)
	}
	blocked := map[string]bool{}
	for _, r := range rules {
		switch r[0] {
		case "path":
			add(&p.Paths, r[1])
		case "dir":
			add(&p.Dirs, r[1])
		case "signer":
			blocked[strings.ToLower(strings.TrimSpace(r[1]))] = true
		}
	}
	for _, f := range learned {
		add(&p.Learned, f)
	}
	// fragments are files the agent wrote itself (not server values), taken as they are
	for publisher, fragment := range signers {
		if blocked[publisher] && !strings.Contains(publisher, "microsoft") && fragment != "" &&
			!strings.ContainsAny(fragment, "\r\n\x00") {
			p.Signers = append(p.Signers, fragment)
		}
	}
	sort.Strings(p.Paths)
	sort.Strings(p.Dirs)
	sort.Strings(p.Learned)
	sort.Strings(p.Signers)
	return p
}

// Rules is how many deny rules the plan holds.
func (p Plan) Rules() int { return len(p.Paths) + len(p.Dirs) + len(p.Learned) + len(p.Signers) }

// Key identifies the plan: the policy is rebuilt only when it changes.
func (p Plan) Key() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// psQuote is a PowerShell single-quoted string literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// ApplyScript builds the policy in workDir and activates it. It prints the
// activation method ("citool" or "cim") on success and throws on failure.
func ApplyScript(p Plan, workDir string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("$ErrorActionPreference = 'Stop'")
	w("$ProgressPreference = 'SilentlyContinue'")
	w("Import-Module ConfigCI")
	w("$dir = %s", psQuote(workDir))
	w("New-Item -ItemType Directory -Force -Path $dir | Out-Null")
	w("$xml = Join-Path $dir 'appcontrol.xml'")
	w("$merged = Join-Path $dir 'appcontrol.merged.xml'")
	w("$bin = Join-Path $dir 'appcontrol.cip'")
	w("$id = %s", psQuote(PolicyID))
	w("Copy-Item -LiteralPath (Join-Path $env:windir 'schemas\\CodeIntegrity\\ExamplePolicies\\AllowAll.xml') -Destination $xml -Force")
	w("$rules = @()")
	w("'step: path and folder rules'")
	for _, path := range p.Paths {
		w("$rules += New-CIPolicyRule -Deny -FilePathRule %s", psQuote(path))
	}
	for _, d := range p.Dirs {
		w("$rules += New-CIPolicyRule -Deny -FilePathRule %s", psQuote(d+`\*`))
	}
	w("'step: learned hashes'")
	for _, f := range p.Learned {
		// a learned file may be gone (deleted, quarantined): its hash cannot be read then
		w("if (Test-Path -LiteralPath %s) { $rules += New-CIPolicyRule -Deny -Level Hash -DriverFilePath %s }",
			psQuote(f), psQuote(f))
	}
	// publisher denies: fragments FragmentScript built once (building one
	// takes minutes; merging it takes a second)
	w("$policies = @($xml)")
	for _, f := range p.Signers {
		w("if (Test-Path -LiteralPath %s) { $policies += %s }", psQuote(f), psQuote(f))
	}
	w("'step: merge'")
	w("if ($rules.Count -gt 0) {")
	w("  Merge-CIPolicy -PolicyPaths $policies -OutputFilePath $merged -Rules $rules | Out-Null")
	w("  Move-Item -LiteralPath $merged -Destination $xml -Force")
	w("} elseif ($policies.Count -gt 1) {")
	w("  Merge-CIPolicy -PolicyPaths $policies -OutputFilePath $merged | Out-Null")
	w("  Move-Item -LiteralPath $merged -Destination $xml -Force")
	w("}")
	// one fixed id: an apply replaces the agent's policy instead of adding one
	w("[xml]$doc = Get-Content -LiteralPath $xml -Raw")
	w("if ($doc.SiPolicy.PolicyID) { $doc.SiPolicy.PolicyID = $id }")
	w("if ($doc.SiPolicy.BasePolicyID) { $doc.SiPolicy.BasePolicyID = $id }")
	w("$doc.Save($xml)")
	w("Set-CIPolicyIdInfo -FilePath $xml -PolicyName %s", psQuote(PolicyName))
	// 0 user mode code integrity, 6 unsigned policy, 16 update without reboot,
	// 18 no runtime admin-only-writable check on FilePath rules (it exists to
	// stop allow rules on user-writable paths; deny rules target exactly those)
	w("foreach ($o in 0, 6, 16, 18) { Set-RuleOption -FilePath $xml -Option $o }")
	if p.Mode == ModeEnforce {
		w("Set-RuleOption -FilePath $xml -Option 3 -Delete")
	} else {
		w("Set-RuleOption -FilePath $xml -Option 3")
	}
	w("'step: convert'")
	w("ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $bin | Out-Null")
	w("'step: activate'")
	w("$ci = Get-Command CiTool.exe -ErrorAction SilentlyContinue")
	w("if ($ci) {")
	w("  & $ci.Source --update-policy $bin -json | Out-Null")
	w("  if ($LASTEXITCODE -ne 0) { throw \"CiTool --update-policy exited $LASTEXITCODE\" }")
	w("  'citool'")
	w("} else {")
	w("  $dest = Join-Path $env:windir (\"System32\\CodeIntegrity\\CiPolicies\\Active\\\" + $id + '.cip')")
	w("  Copy-Item -LiteralPath $bin -Destination $dest -Force")
	w("  $r = Invoke-CimMethod -Namespace root\\Microsoft\\Windows\\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = $dest}")
	w("  if ($r.ReturnValue -ne 0) { throw \"PS_UpdateAndCompareCIPolicy returned $($r.ReturnValue)\" }")
	w("  'cim'")
	w("}")
	return b.String()
}

// FragmentScript builds, once, the policy fragment that denies everything
// the sample's publisher signed: ConfigCI reads the issuing CA and the
// publisher from the sample's signature (New-CIPolicyRule -Level Publisher,
// which takes minutes on a busy host) and the rule is kept as a small policy
// (New-CIPolicy -Rules -UserPEs) that ApplyScript merges in seconds. The
// fragment appears atomically at out; it prints "fragment" on success.
func FragmentScript(sample, out string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("$ErrorActionPreference = 'Stop'")
	w("$ProgressPreference = 'SilentlyContinue'")
	w("Import-Module ConfigCI")
	w("$out = %s", psQuote(out))
	w("$tmp = $out + '.tmp'")
	w("New-Item -ItemType Directory -Force -Path (Split-Path -Parent $out) | Out-Null")
	w("'step: publisher rule from ' + %s", psQuote(sample))
	w("$r = New-CIPolicyRule -Deny -Level Publisher -DriverFilePath %s", psQuote(sample))
	w("if (@($r).Count -eq 0) { throw 'no publisher rule: the sample carries no usable signature' }")
	w("'step: fragment'")
	w("New-CIPolicy -Rules $r -FilePath $tmp -UserPEs | Out-Null")
	w("Move-Item -LiteralPath $tmp -Destination $out -Force")
	w("'fragment'")
	return b.String()
}

// RemoveScript deactivates the agent's policy. It prints "citool" (removed
// now) or "reboot" (the file is gone; Windows unloads it at the next boot),
// or "none" when there was no policy.
func RemoveScript() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("$ErrorActionPreference = 'Stop'")
	w("$ProgressPreference = 'SilentlyContinue'")
	w("$id = %s", psQuote(PolicyID))
	w("$dest =Join-Path $env:windir (\"System32\\CodeIntegrity\\CiPolicies\\Active\\\" + $id + '.cip')")
	w("$ci = Get-Command CiTool.exe -ErrorAction SilentlyContinue")
	w("if ($ci) {")
	w("  $listed = & $ci.Source --list-policies -json | Out-String")
	w("  if ($listed -notmatch [regex]::Escape($id.Trim('{}'))) { 'none'; return }")
	w("  & $ci.Source --remove-policy $id -json | Out-Null")
	w("  if ($LASTEXITCODE -ne 0) { throw \"CiTool --remove-policy exited $LASTEXITCODE\" }")
	w("  'citool'; return")
	w("}")
	w("if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force; 'reboot' } else { 'none' }")
	return b.String()
}
