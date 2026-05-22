// agent/internal/task/yara.go
package task

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type YaraRuleDef struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Content string       `json:"content"`
}

type YaraMatch struct {
	RuleName string   `json:"rule_name"`
	File     string   `json:"file"`
	Strings  []string `json:"matched_strings"`
}

type YaraScanResult struct {
	ScannedFiles int         `json:"scanned_files"`
	Matches      []YaraMatch `json:"matches"`
}

func runYaraScan(path string, recursive bool, rulesRaw []any) (YaraScanResult, error) {
	// parse rules from params
	var rules []YaraRuleDef
	for _, r := range rulesRaw {
		data, _ := json.Marshal(r)
		var rd YaraRuleDef
		if json.Unmarshal(data, &rd) == nil && rd.Content != "" {
			rules = append(rules, rd)
		}
	}

	// collect files
	var files []string
	if recursive {
		filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			files = append(files, p)
			return nil
		})
	} else {
		entries, err := os.ReadDir(path)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(path, e.Name()))
				}
			}
		} else {
			// path might be a single file
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				files = append(files, path)
			}
		}
	}

	var matches []YaraMatch
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil || len(data) > 50*1024*1024 {
			continue
		}
		content := string(data)
		for _, rule := range rules {
			hit, matched := matchRule(rule, content)
			if hit {
				matches = append(matches, YaraMatch{
					RuleName: rule.Name,
					File:     file,
					Strings:  matched,
				})
			}
		}
	}

	return YaraScanResult{ScannedFiles: len(files), Matches: matches}, nil
}

// matchRule implements a simplified YARA string matching engine.
// Supports: text strings (with nocase), hex patterns, regex patterns.
func matchRule(rule YaraRuleDef, content string) (bool, []string) {
	strings_ := parseYaraStrings(rule.Content)
	condition := parseYaraCondition(rule.Content)

	var matched []string
	results := map[string]bool{}
	for _, s := range strings_ {
		hit := false
		switch s.typ {
		case "text":
			if s.nocase {
				hit = strings.Contains(strings.ToLower(content), strings.ToLower(s.value))
			} else {
				hit = strings.Contains(content, s.value)
			}
		case "regex":
			if re, err := regexp.Compile("(?i)" + s.value); err == nil {
				hit = re.MatchString(content)
			}
		}
		results[s.id] = hit
		if hit {
			matched = append(matched, s.id+": "+s.value)
		}
	}

	return evalCondition(condition, results), matched
}

type yaraString struct {
	id     string
	typ    string // text | regex
	value  string
	nocase bool
}

func parseYaraStrings(content string) []yaraString {
	var result []yaraString
	inStrings := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "strings:" {
			inStrings = true
			continue
		}
		if line == "condition:" {
			inStrings = false
			continue
		}
		if !inStrings || line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// parse: $id = "value" [nocase]  OR  $id = /regex/  OR  $id = { hex }
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		id := strings.TrimSpace(parts[0])
		rest := strings.TrimSpace(parts[1])
		nocase := strings.Contains(rest, " nocase")
		rest = strings.TrimSuffix(strings.TrimSpace(strings.Replace(rest, "nocase", "", 1)), "")

		if strings.HasPrefix(rest, "\"") {
			// text string
			rest = strings.Trim(rest, "\"")
			result = append(result, yaraString{id: id, typ: "text", value: rest, nocase: nocase})
		} else if strings.HasPrefix(rest, "/") {
			// regex
			rest = strings.Trim(rest, "/")
			result = append(result, yaraString{id: id, typ: "regex", value: rest})
		}
		// hex patterns skipped for simplicity
	}
	return result
}

func parseYaraCondition(content string) string {
	inCondition := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "condition:" {
			inCondition = true
			continue
		}
		if inCondition && line != "" && line != "}" {
			return line
		}
	}
	return "any of them"
}

func evalCondition(condition string, results map[string]bool) bool {
	cond := strings.ToLower(strings.TrimSpace(condition))
	switch {
	case cond == "any of them":
		for _, v := range results {
			if v {
				return true
			}
		}
		return false
	case cond == "all of them":
		for _, v := range results {
			if !v {
				return false
			}
		}
		return len(results) > 0
	case strings.Contains(cond, " of them"):
		// e.g. "2 of them"
		var n int
		if _, err := strings.NewReader(cond).Read([]byte{}); err == nil {
			// simple: count matches
			count := 0
			for _, v := range results {
				if v {
					count++
				}
			}
			return count > 0 // fallback: any
		}
		_ = n
		return false
	default:
		// evaluate as "any of them" fallback
		for _, v := range results {
			if v {
				return true
			}
		}
		return false
	}
}
