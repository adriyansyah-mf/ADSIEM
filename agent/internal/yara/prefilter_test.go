package yara

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"
)

// The prefilter only removes work: every string's matches are the same
// with it as with a full search of the data.
func TestPrefilterGivesTheSameMatches(t *testing.T) {
	rules := `
rule lit      { strings: $a = "Invoke-Mimikatz" condition: #a > 0 }
rule nc       { strings: $a = "VirtualAlloc" nocase condition: #a > 0 }
rule wd       { strings: $a = "cmd.exe /c" wide ascii condition: #a > 0 }
rule hexjump  { strings: $a = { 4D 5A [2-6] 50 45 00 00 } condition: #a > 0 }
rule hexwild  { strings: $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 } condition: #a > 0 }
rule rx       { strings: $a = /https?:\/\/[a-z0-9.]{3,40}\/gate\.php/ condition: #a > 0 }
rule rxnc     { strings: $a = /powershell\s+-enc/ nocase condition: #a > 0 }
rule dense    { strings: $a = "ABCD" condition: #a > 0 }
rule edge     { strings: $a = "TAILMARK" $b = "HEADMARK" condition: $a and $b }
rule xr       { strings: $a = "secret!" xor(1-3) condition: #a > 0 }
`
	var data bytes.Buffer
	data.WriteString("HEADMARK")
	for i := 0; i < 6000; i++ { // more hits than maxAtomHits: a dense atom
		data.WriteString("ABCD.")
	}
	data.WriteString("invoke-mimikatz Invoke-Mimikatz virtualALLOC VIRTUALALLOC ")
	data.Write([]byte{'c', 0, 'm', 0, 'd', 0, '.', 0, 'e', 0, 'x', 0, 'e', 0, ' ', 0, '/', 0, 'c', 0})
	data.WriteString(" cmd.exe /c ")
	data.Write([]byte{0x4d, 0x5a, 1, 2, 3, 0x50, 0x45, 0, 0, 0x68, 1, 2, 3, 4, 0xe8, 5, 6, 7, 8, 0x83, 0xc4, 0x04})
	data.WriteString(" http://evil.example.com/gate.php POWERSHELL   -ENC ")
	for _, c := range []byte("secret!") {
		data.WriteByte(c ^ 2)
	}
	data.WriteString("TAILMARK")
	b := data.Bytes()

	r, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	with := r.allMatches(b, true)
	without := r.allMatches(b, false)
	if !reflect.DeepEqual(with, without) {
		t.Fatalf("matches differ\nwith prefilter:    %v\nwithout prefilter: %v", with, without)
	}
	for _, name := range []string{"lit", "nc", "wd", "hexjump", "hexwild", "rx", "rxnc", "dense", "edge", "xr"} {
		if len(with[name]) == 0 {
			t.Errorf("rule %s did not match", name)
		}
	}
	if n := len(with["dense/$a"]); n != 6000 {
		t.Errorf("dense string: %d matches, want 6000", n)
	}
}

// allMatches: every string's match offsets by "rule/$id", and the matching
// rules by name, with the prefilter on or off.
func (r *Rules) allMatches(data []byte, prefilter bool) map[string][]int {
	sc := newScanCtx(context.Background(), r, data)
	if !prefilter {
		sc.pf = nil
	}
	out := map[string][]int{}
	for _, ru := range r.rules {
		for _, s := range ru.strs {
			for _, m := range sc.stringMatches(s) {
				k := fmt.Sprintf("%s/$%s", ru.name, s.id)
				out[k] = append(out[k], m.off)
			}
		}
		if sc.ruleResult(ru) {
			out[ru.name] = []int{1}
		}
	}
	return out
}
