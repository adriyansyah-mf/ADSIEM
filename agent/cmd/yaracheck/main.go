// Command yaracheck validates and runs YARA rules with the exact engine the
// agents use (internal/yara), for server-api: it ships in the server-api
// image so a rule that validates on the server compiles on every endpoint.
//
//	yaracheck capabilities                       engine version, modules, limits
//	yaracheck validate < rule.yar                 diagnostics, rule names, fingerprint
//	yaracheck scan -rules rule.yar FILE...        matches per file
//
// Output is one JSON object on stdout; the exit code is 0 unless the
// command itself could not run (an invalid rule is a result, not a failure).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/siem-platform/agent/internal/yara"
)

const (
	maxRuleBytes = 1 << 20
	maxScanBytes = 50 << 20 // the agents' on-demand scan cap (internal/task/yara.go)
)

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: yaracheck capabilities | validate | scan -rules FILE PATH..."))
	}
	var out any
	var err error
	switch os.Args[1] {
	case "capabilities":
		out = capabilities()
	case "validate":
		out, err = validate(os.Stdin)
	case "scan":
		out, err = scan(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func fail(err error) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
	os.Exit(2)
}

type Capabilities struct {
	Engine          string   `json:"engine"`
	Version         string   `json:"version"`
	Modules         []string `json:"modules"`
	StringModifiers []string `json:"string_modifiers"`
	MaxRuleBytes    int      `json:"max_rule_bytes"`
	MaxScanBytes    int      `json:"max_scan_bytes"`
}

func capabilities() Capabilities {
	return Capabilities{
		Engine: "siem-agent pure-Go YARA", Version: yara.EngineVersion, Modules: yara.SupportedModules(),
		StringModifiers: []string{"ascii", "wide", "nocase", "fullword", "xor", "base64", "base64wide", "private"},
		MaxRuleBytes:    maxRuleBytes, MaxScanBytes: maxScanBytes,
	}
}

type Validation struct {
	OK            bool     `json:"ok"`
	Error         string   `json:"error,omitempty"`
	Line          int      `json:"line,omitempty"`
	Rules         []string `json:"rules"`
	Fingerprint   string   `json:"fingerprint"`
	EngineVersion string   `json:"engine_version"`
}

// Fingerprint identifies exactly the text that was validated: a validation
// or test result only counts for the rule content with this fingerprint.
func Fingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func validate(r io.Reader) (Validation, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRuleBytes+1))
	if err != nil {
		return Validation{}, err
	}
	text := string(data)
	v := Validation{Fingerprint: Fingerprint(text), EngineVersion: yara.EngineVersion, Rules: []string{}}
	if len(data) > maxRuleBytes {
		v.Error = fmt.Sprintf("rule text is larger than %d bytes", maxRuleBytes)
		return v, nil
	}
	rules, err := yara.Compile(text)
	if err != nil {
		v.Error = err.Error()
		var ye *yara.Error
		if errors.As(err, &ye) {
			v.Line = ye.Line
		}
		return v, nil
	}
	v.Rules = rules.Names()
	v.OK = len(v.Rules) > 0
	if !v.OK {
		v.Error = "the text defines no rule"
	}
	return v, nil
}

type FileResult struct {
	Path    string   `json:"path"`
	Rules   []string `json:"rules"`
	Strings []string `json:"strings,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type ScanResult struct {
	Fingerprint string       `json:"fingerprint"`
	Files       []FileResult `json:"files"`
	Matched     int          `json:"matched"`
}

func scan(args []string) (ScanResult, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	rulesPath := fs.String("rules", "", "rule file")
	timeout := fs.Duration("timeout", 60*time.Second, "overall time limit")
	if err := fs.Parse(args); err != nil {
		return ScanResult{}, err
	}
	data, err := os.ReadFile(*rulesPath)
	if err != nil {
		return ScanResult{}, err
	}
	rules, err := yara.Compile(string(data))
	if err != nil {
		return ScanResult{}, fmt.Errorf("rule does not compile: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	out := ScanResult{Fingerprint: Fingerprint(string(data)), Files: []FileResult{}}
	for _, path := range fs.Args() {
		fr := FileResult{Path: path, Rules: []string{}}
		res, err := rules.ScanFile(ctx, path, maxScanBytes)
		if err != nil {
			fr.Error = err.Error()
		}
		for _, m := range res.Matches {
			fr.Rules = append(fr.Rules, m.Rule)
			for _, s := range m.Strings {
				fr.Strings = append(fr.Strings, fmt.Sprintf("%s:%s@%d", m.Rule, s.ID, s.Offset))
			}
		}
		if len(fr.Rules) > 0 {
			out.Matched++
		}
		out.Files = append(out.Files, fr)
	}
	return out, nil
}
