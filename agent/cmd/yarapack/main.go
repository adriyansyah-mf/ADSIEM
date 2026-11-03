// Command yarapack builds the community YARA pack (yara/community) from a
// YARA-Forge release (https://github.com/YARAHQ/yara-forge):
//
//	yarapack -forge yara-rules-core.yar -out ../yara/community -benign /usr/bin,/opt/app
//
// It keeps the rule sets whose licence allows use in a commercial product
// (allowedLicences; the rest, including sets with no licence, are left out),
// keeps each rule only when the agent's own engine compiles it (with the
// private rules it needs), drops every rule that matches a known-good file
// under -benign, and writes one file per rule set with its source, licence
// and attribution, plus MANIFEST.json.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/yara"
)

// allowedLicences: YARA-Forge rule set name -> licence. Only these are
// packed. DRL 1.1 allows use in products with attribution (kept in each
// rule's meta and in the file header).
var allowedLicences = map[string]string{
	"ReversingLabs":    "MIT",
	"BinaryAlert":      "Apache-2.0",
	"ESET":             "BSD-2-Clause",
	"FireEye-RT":       "BSD-2-Clause",
	"GCTI":             "Apache-2.0",
	"Trellix ARC":      "Apache-2.0",
	"Telekom Security": "MIT",
	"Volexity":         "BSD-2-Clause",
	"JPCERTCC":         "BSD-3-Clause",
	"Elceef":           "MIT",
	"DitekSHen":        "BSD-2-Clause",
	"WithSecureLabs":   "BSD-2-Clause",
	"LOLDrivers":       "Apache-2.0",
	"Signature Base":   "DRL-1.1",
	"SEKOIA":           "DRL-1.1",
	"Synacktiv":        "DRL-1.1",
	"Dr4k0nia":         "DRL-1.1",
	"Cod3nym":          "DRL-1.1",
}

type ruleText struct {
	name, text string
}

type ruleSet struct {
	name, repo, commit, licence string
	licenceText                 string
	rules                       []ruleText
}

var (
	reSection = regexp.MustCompile(`(?m)^/\*\n \* YARA Rule Set\n`)
	reRule    = regexp.MustCompile(`^(?:(?:private|global)\s+)*rule\s+([A-Za-z0-9_]+)`)
	reField   = func(name string) *regexp.Regexp { return regexp.MustCompile(`\* ` + name + `: (.*)`) }
)

func field(block, name string) string {
	if m := reField(name).FindStringSubmatch(block); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func parse(text string) []ruleSet {
	locs := reSection.FindAllStringIndex(text, -1)
	var sets []ruleSet
	for i, loc := range locs {
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := text[loc[0]:end]
		head := block[:strings.Index(block, "*/")+2]
		rs := ruleSet{name: field(head, "Repository Name"), repo: field(head, "Repository"),
			commit: field(head, "Git Commit")}
		if j := strings.Index(head, "* LICENSE"); j >= 0 {
			var lines []string
			for _, l := range strings.Split(head[j+len("* LICENSE"):], "\n") {
				l = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(l), "*"))
				if l != "" && l != "/" {
					lines = append(lines, l)
				}
			}
			rs.licenceText = strings.Join(lines, "\n")
		}
		var cur []string
		var name string
		for _, line := range strings.Split(block[len(head):], "\n") {
			if name == "" {
				if m := reRule.FindStringSubmatch(line); m != nil {
					name, cur = m[1], []string{line}
				}
				continue
			}
			cur = append(cur, line)
			if line == "}" {
				rs.rules = append(rs.rules, ruleText{name: name, text: strings.Join(cur, "\n")})
				name, cur = "", nil
			}
		}
		sets = append(sets, rs)
	}
	return sets
}

const imports = "import \"pe\"\nimport \"hash\"\nimport \"math\"\n\n"

// compiles reports whether the agent's engine compiles text.
func compiles(text string) error {
	_, errs := yara.CompileSources([]yara.Source{{Namespace: "t", Text: imports + text}})
	if len(errs) > 0 {
		return errs[0].Err
	}
	return nil
}

// keepCompiling returns the rules that compile, each with the rules of its
// set it refers to placed before it (private helper rules).
func keepCompiling(rs ruleSet) (kept []ruleText, dropped map[string]string) {
	byName := map[string]ruleText{}
	for _, r := range rs.rules {
		byName[r.name] = r
	}
	dropped = map[string]string{}
	in := map[string]bool{}
	var add func(r ruleText, depth int) bool
	add = func(r ruleText, depth int) bool {
		if in[r.name] {
			return true
		}
		err := compiles(r.text)
		if err == nil {
			kept = append(kept, r)
			in[r.name] = true
			return true
		}
		if depth < 3 {
			// a reference to another rule of the set: add it first, then retry
			var deps []ruleText
			for n, d := range byName {
				if n != r.name && regexp.MustCompile(`\b`+n+`\b`).MatchString(r.text[strings.Index(r.text, "condition:"):]) {
					deps = append(deps, d)
				}
			}
			if len(deps) > 0 {
				var all []string
				for _, d := range deps {
					all = append(all, d.text)
				}
				if compiles(strings.Join(append(all, r.text), "\n\n")) == nil {
					for _, d := range deps {
						if !add(d, depth+1) {
							dropped[r.name] = "needs " + d.name
							return false
						}
					}
					kept = append(kept, r)
					in[r.name] = true
					return true
				}
			}
		}
		dropped[r.name] = err.Error()
		return false
	}
	for _, r := range rs.rules {
		if strings.Contains(r.text, "condition:") {
			add(r, 0)
		}
	}
	return kept, dropped
}

// benignHits returns, per rule name, a known-good file it matched.
func benignHits(rules *yara.Rules, dirs []string) (map[string]string, int) {
	hits := map[string]string{}
	files := 0
	for _, d := range dirs {
		filepath.WalkDir(d, func(p string, de fs.DirEntry, err error) error {
			if err != nil || !de.Type().IsRegular() {
				return nil
			}
			if info, err := de.Info(); err != nil || info.Size() == 0 || info.Size() > 32<<20 {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			files++
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			res, err := rules.Scan(ctx, b)
			cancel()
			if err != nil {
				return nil
			}
			for _, m := range res.Matches {
				if _, ok := hits[m.Rule]; !ok {
					hits[m.Rule] = p
				}
			}
			return nil
		})
	}
	return hits, files
}

type manifestEntry struct {
	Set           string `json:"set"`
	File          string `json:"file"`
	Repository    string `json:"repository"`
	Commit        string `json:"commit"`
	Licence       string `json:"licence"`
	Rules         int    `json:"rules"`
	NotCompiled   int    `json:"dropped_not_compiled"`
	FalsePositive int    `json:"dropped_false_positive"`
}

func slug(s string) string {
	return strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(s), "_"), "_")
}

func main() {
	forge := flag.String("forge", "", "YARA-Forge package file (yara-rules-core.yar)")
	out := flag.String("out", "../yara/community", "output directory")
	benign := flag.String("benign", "", "comma-separated directories of known-good files: rules matching them are dropped")
	release := flag.String("release", "", "YARA-Forge release name, for the file headers")
	drop := flag.String("drop", "", "comma-separated rule names to leave out (false positives found earlier)")
	flag.Parse()
	b, err := os.ReadFile(*forge)
	if err != nil {
		log.Fatal(err)
	}
	sets := parse(string(b))
	type packed struct {
		rs   ruleSet
		kept []ruleText
		drop map[string]string
	}
	var packs []*packed
	var all []yara.Source
	for _, rs := range sets {
		lic, ok := allowedLicences[rs.name]
		if !ok {
			log.Printf("skip %-22s %4d rules: licence not allowed", rs.name, len(rs.rules))
			continue
		}
		rs.licence = lic
		kept, drop := keepCompiling(rs)
		log.Printf("set  %-22s %4d rules, %4d compile, %4d do not", rs.name, len(rs.rules), len(kept), len(drop))
		p := &packed{rs: rs, kept: kept, drop: drop}
		packs = append(packs, p)
		var texts []string
		for _, r := range kept {
			texts = append(texts, r.text)
		}
		all = append(all, yara.Source{Namespace: rs.name, Text: imports + strings.Join(texts, "\n\n")})
	}
	fp := map[string]string{}
	if *benign != "" {
		rules, errs := yara.CompileSources(all)
		for _, e := range errs {
			log.Fatalf("combined pack does not compile: %v", e)
		}
		start := time.Now()
		hits, n := benignHits(rules, strings.Split(*benign, ","))
		log.Printf("benign: %d files in %s, %d rules matched something", n, time.Since(start).Round(time.Second), len(hits))
		fp = hits
	}
	for _, name := range strings.Split(*drop, ",") {
		if name = strings.TrimSpace(name); name != "" {
			fp[name] = "-drop"
		}
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	var manifest []manifestEntry
	total := 0
	for _, p := range packs {
		var texts []string
		nfp := 0
		for _, r := range p.kept {
			if where, bad := fp[r.name]; bad {
				// keep private helpers others need; they never alert themselves
				if !strings.HasPrefix(strings.TrimSpace(r.text), "private") {
					log.Printf("drop %s: matched known-good %s", r.name, where)
					nfp++
					continue
				}
			}
			texts = append(texts, r.text)
		}
		if len(texts) == 0 {
			continue
		}
		file := slug(p.rs.name) + ".yar"
		header := fmt.Sprintf("// Community rule pack: %s rules (%s licence), from YARA-Forge %s.\n"+
			"// Source: %s (commit %s). Rule authors and references are kept in each rule's meta.\n"+
			"// Generated by agent/cmd/yarapack: rules the agent's engine does not compile and\n"+
			"// rules matching known-good files were left out. Do not edit; regenerate.\n//\n",
			p.rs.name, p.rs.licence, *release, p.rs.repo, p.rs.commit)
		for _, l := range strings.Split(p.rs.licenceText, "\n") {
			header += "// " + l + "\n"
		}
		content := header + "\n" + imports + strings.Join(texts, "\n\n") + "\n"
		if err := compiles(strings.Join(texts, "\n\n")); err != nil {
			log.Fatalf("%s does not compile after filtering: %v", file, err)
		}
		if err := os.WriteFile(filepath.Join(*out, file), []byte(content), 0o644); err != nil {
			log.Fatal(err)
		}
		manifest = append(manifest, manifestEntry{Set: p.rs.name, File: file, Repository: p.rs.repo,
			Commit: p.rs.commit, Licence: p.rs.licence, Rules: len(texts), NotCompiled: len(p.drop), FalsePositive: nfp})
		total += len(texts)
	}
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].Rules > manifest[j].Rules })
	mb, _ := json.MarshalIndent(map[string]any{"source": "YARA-Forge " + *release, "rules": total, "sets": manifest}, "", " ")
	if err := os.WriteFile(filepath.Join(*out, "MANIFEST.json"), append(mb, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d rules in %d files to %s", total, len(manifest), *out)
}
