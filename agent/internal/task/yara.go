// agent/internal/task/yara.go
package task

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/siem-platform/agent/internal/yara"
)

type YaraRuleDef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

type YaraMatch struct {
	RuleName  string   `json:"rule_name"`
	Namespace string   `json:"namespace,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	File      string   `json:"file"`
	Strings   []string `json:"matched_strings"`
}

type YaraRuleError struct {
	Rule  string `json:"rule"`
	Error string `json:"error"`
}

type YaraScanResult struct {
	ScannedFiles int             `json:"scanned_files"`
	SkippedFiles int             `json:"skipped_files"`
	Matches      []YaraMatch     `json:"matches"`
	RuleErrors   []YaraRuleError `json:"rule_errors,omitempty"`
	Warnings     []string        `json:"warnings,omitempty"`
}

const (
	yaraMaxFileSize = 50 << 20
	yaraTaskTimeout = 15 * time.Minute
)

// compileYaraRules compiles each rule definition in its own namespace;
// definitions that do not compile are reported, not fatal.
func compileYaraRules(rulesRaw []any) (*yara.Rules, []YaraRuleError) {
	var srcs []yara.Source
	for _, r := range rulesRaw {
		data, _ := json.Marshal(r)
		var rd YaraRuleDef
		if json.Unmarshal(data, &rd) == nil && rd.Content != "" {
			name := rd.Name
			if name == "" {
				name = rd.ID
			}
			srcs = append(srcs, yara.Source{Namespace: name, Text: rd.Content})
		}
	}
	rules, errs := yara.CompileSources(srcs)
	var out []YaraRuleError
	for _, e := range errs {
		out = append(out, YaraRuleError{Rule: e.Namespace, Error: e.Err.Error()})
	}
	return rules, out
}

// describeStrings renders matched strings as "$id@offset: data".
func describeStrings(m yara.RuleMatch) []string {
	out := make([]string, 0, len(m.Strings))
	for _, s := range m.Strings {
		out = append(out, s.ID+"@"+strconv.FormatInt(s.Offset, 10)+": "+printable(s.Data))
	}
	return out
}

func printable(b []byte) string {
	q := strconv.QuoteToASCII(string(b))
	return q[1 : len(q)-1]
}

func runYaraScan(path string, recursive bool, rulesRaw []any) (YaraScanResult, error) {
	rules, ruleErrs := compileYaraRules(rulesRaw)
	res := YaraScanResult{RuleErrors: ruleErrs}
	if rules.Len() == 0 {
		return res, fmt.Errorf("no YARA rule compiled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), yaraTaskTimeout)
	defer cancel()

	var files []string
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		files = []string{path}
	} else if recursive {
		filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				files = append(files, p)
			}
			return nil
		})
	} else if entries, err := os.ReadDir(path); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
	}

	for _, file := range files {
		if ctx.Err() != nil {
			res.Warnings = append(res.Warnings, "scan timed out; remaining files skipped")
			break
		}
		sr, err := rules.ScanFile(ctx, file, yaraMaxFileSize)
		if err != nil {
			res.SkippedFiles++
			continue
		}
		res.ScannedFiles++
		res.Warnings = append(res.Warnings, sr.Warnings...)
		for _, m := range sr.Matches {
			res.Matches = append(res.Matches, YaraMatch{
				RuleName: m.Rule, Namespace: m.Namespace, Tags: m.Tags, File: file, Strings: describeStrings(m),
			})
		}
	}
	return res, nil
}

// ─── live response plugin ────────────────────────────────────────

func pluginYara(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	root := argString(args, "path", os.TempDir())
	recursive := argBool(args, "recursive", true)
	rulesRaw, _ := args["rules"].([]any)
	rules, ruleErrs := compileYaraRules(rulesRaw)
	for _, e := range ruleErrs {
		if err := emit(map[string]any{"Rule": e.Rule, "Error": e.Error}); err != nil {
			return err
		}
	}
	if rules.Len() == 0 {
		return fmt.Errorf("no YARA rules supplied")
	}
	scan := func(p string) error {
		res, err := rules.ScanFile(ctx, p, yaraMaxFileSize)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
		for _, m := range res.Matches {
			info, _ := os.Stat(p)
			var size int64
			if info != nil {
				size = info.Size()
			}
			if err := emit(map[string]any{
				"Rule": m.Rule, "Namespace": m.Namespace, "Tags": m.Tags,
				"File": p, "Size": size, "Strings": describeStrings(m),
			}); err != nil {
				return err
			}
		}
		return nil
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (!recursive || skipPseudoFS(root, p)) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return scan(p)
	})
}
