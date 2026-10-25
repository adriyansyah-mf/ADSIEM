package yara

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Rules come from the server and data from any file on the host, so
// neither may crash the agent.

func FuzzCompile(f *testing.F) {
	f.Add(`rule a { strings: $a = "x" condition: $a }`)
	f.Add(`import "pe" rule a { condition: pe.imports("k.dll", "f") and for any s in pe.sections : (s.name == ".text") }`)
	f.Add(`rule a { strings: $a = { 4D 5A [0-4] ( 90 | ?0 ) ~00 } condition: #a > 1 and @a[1] < 10 }`)
	f.Add(`rule a { strings: $a = /ab+[c-e]{2,3}/is wide condition: for all i in (1..#a) : (!a[i] > 1) }`)
	f.Add(`rule a { strings: $a = "x" xor(1-3) $b = "y" base64 condition: 50% of them }`)
	f.Fuzz(func(t *testing.T, src string) {
		rules, err := Compile(src)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = rules.Scan(ctx, []byte("MZ\x90\x00 hello xyz \x7fELF abcabc"))
	})
}

var fuzzRules = `
import "pe"
import "elf"
import "math"
import "hash"
rule p { condition: pe.is_pe and (pe.imports("kernel32.dll") > 0 or pe.exports("x") or pe.imphash() == "" or
  for any s in pe.sections : (s.name == ".text" and math.entropy(s.raw_data_offset, s.raw_data_size) > 7)) }
rule e { condition: for any s in elf.segments : (s.type == elf.PT_LOAD and hash.md5(s.offset, s.file_size) != "") }
rule s { strings: $a = { 4D 5A [2-8] 50 45 } $b = /https?:\/\/[a-z.]{4,}/ nocase $c = "cmd" wide ascii fullword
  condition: any of them or entrypoint > 0 or uint32(@a[1] + 4) == 0 }
`

func FuzzScan(f *testing.F) {
	rules, err := Compile(fuzzRules)
	if err != nil {
		f.Fatal(err)
	}
	fixtures, _ := filepath.Glob("testdata/differential/fixtures/*")
	for _, p := range fixtures {
		if b, err := os.ReadFile(p); err == nil && len(b) < 1<<16 {
			f.Add(b)
		}
	}
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := rules.Scan(context.Background(), data); err != nil {
			t.Fatal(err)
		}
	})
}

func TestScanCancelled(t *testing.T) {
	rules, err := Compile(`rule a { strings: $a = /a.*b/s condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rules.Scan(ctx, make([]byte, 1<<20)); err == nil {
		t.Fatal("scan with a cancelled context returned no error")
	}
}

// A pathological string must stop at the step budget with a warning
// instead of running for minutes.
func TestStepBudget(t *testing.T) {
	rules, err := Compile(`rule a { strings: $a = { 61 [0-] 62 [0-] 63 [0-] 64 } condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	// The default budget is seconds of work, much more under -race; a
	// smaller one shows the same thing quickly.
	defer func(b int64) { stepBudget = b }(stepBudget)
	stepBudget = 5_000_000
	data := make([]byte, 4<<20)
	for i := range data {
		data[i] = 'a'
	}
	start := time.Now()
	res, err := rules.Scan(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected a budget warning")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("budget not enforced: scan took %v", d)
	}
}

func TestCompileSourcesKeepsGoodSources(t *testing.T) {
	rules, errs := CompileSources([]Source{
		{Namespace: "good", Text: `rule a { condition: true }`},
		{Namespace: "bad", Text: `rule b { condition: nope }`},
		{Namespace: "good2", Text: `rule a { condition: filesize > 0 }`},
	})
	if len(errs) != 1 || errs[0].Namespace != "bad" {
		t.Fatalf("errs = %v", errs)
	}
	res, err := rules.Scan(context.Background(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("matches = %+v", res.Matches)
	}
}

func TestReportedMatchData(t *testing.T) {
	rules, err := Compile(`rule a : t1 { meta: score = 5 strings: $a = "evil" $p = "x" private condition: $a and $p }`)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rules.Scan(context.Background(), []byte("x evil evil"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %+v", res.Matches)
	}
	m := res.Matches[0]
	if m.Rule != "a" || len(m.Tags) != 1 || m.Meta[0].Value != int64(5) {
		t.Fatalf("match = %+v", m)
	}
	if len(m.Strings) != 2 || m.Strings[0].ID != "$a" || m.Strings[0].Offset != 2 || string(m.Strings[1].Data) != "evil" {
		t.Fatalf("strings = %+v (private strings must not be reported)", m.Strings)
	}
}
