package yara

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type diffCase struct {
	Name        string   `yaml:"name"`
	Rules       string   `yaml:"rules"`
	Inputs      []string `yaml:"inputs"`
	Unsupported string   `yaml:"unsupported"`
}

type diffMatch struct {
	Rule    string  `json:"rule"`
	Strings [][]any `json:"strings"`
}

type diffExpected struct {
	Error   string        `json:"error"`
	Results [][]diffMatch `json:"results"`
}

func loadDiffInput(t *testing.T, spec string) []byte {
	t.Helper()
	switch {
	case strings.HasPrefix(spec, "hex:"):
		b, err := hex.DecodeString(spec[4:])
		if err != nil {
			t.Fatal(err)
		}
		return b
	case strings.HasPrefix(spec, "rep:"):
		var parts [][]any
		if err := json.Unmarshal([]byte(spec[4:]), &parts); err != nil {
			t.Fatal(err)
		}
		var out []byte
		for _, p := range parts {
			piece := latin1Bytes(p[0].(string))
			for i := 0; i < int(p[1].(float64)); i++ {
				out = append(out, piece...)
			}
		}
		return out
	case strings.HasPrefix(spec, "file:"):
		b, err := os.ReadFile(filepath.Join("testdata", "differential", "fixtures", spec[5:]))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return latin1Bytes(spec)
}

// latin1Bytes maps each rune (all < 256 in the cases) to one byte, the
// same encoding gen_expected.py uses.
func latin1Bytes(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r))
	}
	return out
}

// scanAll returns, like yara-python, every match of every non-private
// string of each matching rule.
func scanAll(t *testing.T, rules *Rules, data []byte) []diffMatch {
	t.Helper()
	res, err := rules.Scan(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	sc := newScanCtx(context.Background(), rules, data)
	out := []diffMatch{}
	for _, m := range res.Matches {
		dm := diffMatch{Rule: m.Rule, Strings: [][]any{}}
		for _, r := range rules.rules {
			if r.name != m.Rule || r.ns != m.Namespace {
				continue
			}
			for _, s := range r.strs {
				if s.private {
					continue
				}
				for _, sm := range sc.stringMatches(s) {
					dm.Strings = append(dm.Strings, []any{"$" + s.id, float64(sm.off), float64(sm.len)})
				}
			}
		}
		sort.SliceStable(dm.Strings, func(i, j int) bool {
			a, b := dm.Strings[i], dm.Strings[j]
			if a[0] != b[0] {
				return a[0].(string) < b[0].(string)
			}
			return a[1].(float64) < b[1].(float64)
		})
		out = append(out, dm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// TestDifferential checks the engine against libyara's recorded output
// (testdata/differential/expected.json, made by gen_expected.py).
func TestDifferential(t *testing.T) {
	files, err := filepath.Glob("testdata/differential/cases*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no case files: %v", err)
	}
	var cases []diffCase
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cs []diffCase
		if err := yaml.Unmarshal(raw, &cs); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		cases = append(cases, cs...)
	}
	raw, err := os.ReadFile("testdata/differential/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Cases map[string]diffExpected `json:"cases"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			want, ok := expected.Cases[c.Name]
			if !ok {
				t.Fatalf("no expected result; run gen_expected.py")
			}
			rules, err := Compile(c.Rules)
			switch {
			case want.Error != "":
				if err == nil {
					t.Fatalf("libyara rejects these rules (%s), the engine accepts them", want.Error)
				}
				return
			case c.Unsupported != "":
				if err == nil {
					t.Fatalf("marked unsupported (%s) but compiled", c.Unsupported)
				}
				return
			case err != nil:
				t.Fatalf("compile: %v", err)
			}
			for i, spec := range c.Inputs {
				got := scanAll(t, rules, loadDiffInput(t, spec))
				w := want.Results[i]
				if w == nil {
					w = []diffMatch{}
				}
				for j := range w {
					if w[j].Strings == nil {
						w[j].Strings = [][]any{}
					}
				}
				if !reflect.DeepEqual(got, w) {
					gj, _ := json.Marshal(got)
					wj, _ := json.Marshal(w)
					t.Errorf("input %d %s:\n got  %s\n want %s", i, shortSpec(spec), gj, wj)
				}
			}
		})
	}
}

func shortSpec(s string) string {
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return fmt.Sprintf("%q", s)
}
