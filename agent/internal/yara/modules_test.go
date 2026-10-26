package yara

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestModuleData compares the pe and elf module data for each fixture
// with the dump libyara produced (expected.json "modules"). Fields the
// engine does not declare are skipped; every declared field must agree,
// including being absent (undefined) where libyara leaves it unset.
func TestModuleData(t *testing.T) {
	raw, err := os.ReadFile("testdata/differential/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Modules map[string]map[string]map[string]any `json:"modules"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected.Modules) == 0 {
		t.Fatal("no module dumps in expected.json")
	}
	for fixture, mods := range expected.Modules {
		data, err := os.ReadFile(filepath.Join("testdata", "differential", "fixtures", fixture))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"pe", "elf"} {
			t.Run(fixture+"/"+name, func(t *testing.T) {
				m := modules[name]
				sc := newScanCtx(context.Background(), &Rules{}, data)
				got := sc.module(m).root
				want := mods[name]
				if want == nil {
					want = map[string]any{}
				}
				var diffs []string
				compareStruct(name, m.schema, got, want, &diffs)
				sort.Strings(diffs)
				for _, d := range diffs {
					t.Error(d)
				}
			})
		}
	}
}

func compareStruct(path string, s *schema, got value, want map[string]any, diffs *[]string) {
	for field, fs := range s.fields {
		if fs.t == tyFunc || fs.konst != nil {
			continue
		}
		w, inWant := want[field]
		var g value
		if got.k == tyStruct {
			g = got.m[field]
		}
		p := path + "." + field
		if !inWant {
			if g.k != tyUndef && !emptyCollection(g) {
				*diffs = append(*diffs, fmt.Sprintf("%s: libyara leaves it undefined, engine has %s", p, show(g)))
			}
			continue
		}
		compareValue(p, fs, g, w, diffs)
	}
}

func emptyCollection(v value) bool {
	return (v.k == tyArray && len(v.a) == 0) || (v.k == tyStruct && len(v.m) == 0)
}

func compareValue(path string, s *schema, g value, w any, diffs *[]string) {
	switch s.t {
	case tyInt:
		f, ok := w.(float64)
		if !ok || g.k != tyInt || g.i != int64(f) {
			*diffs = append(*diffs, fmt.Sprintf("%s: got %s, libyara %v", path, show(g), w))
		}
	case tyFloat:
		f, ok := w.(float64)
		if !ok || g.k != tyFloat || g.f != f {
			*diffs = append(*diffs, fmt.Sprintf("%s: got %s, libyara %v", path, show(g), w))
		}
	case tyStr:
		ws, ok := w.(string)
		if !ok || g.k != tyStr || string(latin1Bytes(ws)) != g.s {
			*diffs = append(*diffs, fmt.Sprintf("%s: got %s, libyara %q", path, show(g), w))
		}
	case tyStruct:
		wm, ok := w.(map[string]any)
		if !ok {
			*diffs = append(*diffs, fmt.Sprintf("%s: libyara value is not a structure", path))
			return
		}
		compareStruct(path, s, g, wm, diffs)
	case tyArray:
		wa, ok := w.([]any)
		if !ok {
			*diffs = append(*diffs, fmt.Sprintf("%s: libyara value is not an array", path))
			return
		}
		if len(wa) != len(g.a) {
			*diffs = append(*diffs, fmt.Sprintf("%s: %d items, libyara %d", path, len(g.a), len(wa)))
			return
		}
		for i := range wa {
			compareValue(fmt.Sprintf("%s[%d]", path, i), s.elem, g.a[i], wa[i], diffs)
		}
	}
}

func show(v value) string {
	switch v.k {
	case tyUndef:
		return "undefined"
	case tyInt:
		return fmt.Sprint(v.i)
	case tyFloat:
		return fmt.Sprint(v.f)
	case tyStr:
		return fmt.Sprintf("%q", v.s)
	case tyArray:
		return fmt.Sprintf("array(%d)", len(v.a))
	}
	return v.k.String()
}
