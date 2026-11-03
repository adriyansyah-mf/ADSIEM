package yara

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProfilePack scans the files in YARA_PROF_FILES with the rules in
// YARA_PROF_RULES (a directory of .yar) and reports prefilter statistics;
// run with -cpuprofile to see where scan time goes.
func TestProfilePack(t *testing.T) {
	dir, files := os.Getenv("YARA_PROF_RULES"), os.Getenv("YARA_PROF_FILES")
	if dir == "" || files == "" {
		t.Skip("set YARA_PROF_RULES and YARA_PROF_FILES")
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.yar"))
	var srcs []Source
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		srcs = append(srcs, Source{Namespace: filepath.Base(p), Text: string(b)})
	}
	rules, errs := CompileSources(srcs)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	pf := rules.prefilter()
	always, lens := 0, map[int]int{}
	var alwaysSamples []string
	for _, ru := range rules.rules {
		for _, s := range ru.strs {
			if pf.always[s.gid] {
				always++
				if len(alwaysSamples) < 15 {
					alwaysSamples = append(alwaysSamples, ru.name+" $"+s.id+" "+trunc(s.src, 60))
				}
			}
		}
	}
	for _, a := range pf.strsOf {
		lens[len(a)]++
	}
	t.Logf("strings %d, always searched %d, atoms %d", pf.nStrings, always, len(pf.strsOf))
	for _, s := range alwaysSamples {
		t.Logf("  always: %s", s)
	}
	var total time.Duration
	for _, f := range strings.Split(files, ",") {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		sc := newScanCtx(context.Background(), rules, data)
		n := 0
		for _, p := range sc.pf.possible {
			if p {
				n++
			}
		}
		if _, err := rules.Scan(context.Background(), data); err != nil {
			t.Fatal(err)
		}
		d := time.Since(start)
		total += d
		t.Logf("%s: %d bytes, %d strings possible, %s", filepath.Base(f), len(data), n, d)
	}
	t.Logf("total %s", total)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
