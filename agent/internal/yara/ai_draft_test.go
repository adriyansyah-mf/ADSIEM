package yara

import (
	"context"
	"os"
	"testing"
)

// testdata/ai_draft.yar is the exact shape server-api's yara_drafting.build_rule
// writes (meta with provenance, escaped text, wide/nocase modifiers, hex with
// jumps, a regex, a type guard and "N of them"). The agents' engine must
// compile it, or AI drafts could never be validated against it.
func TestAIDraftRuleShapeCompilesAndMatches(t *testing.T) {
	src, err := os.ReadFile("testdata/ai_draft.yar")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Compile(string(src))
	if err != nil {
		t.Fatalf("the drafting format must compile: %v", err)
	}
	sample := append([]byte("MZ\x00\x90\x00\x00PE"), []byte("...C:\\build\\stage2\\loader.pdb...stage2_0badc0de.dat")...)
	res, err := rules.Scan(context.Background(), sample)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("want the draft to match its sample, got %+v", res)
	}
	benign := append([]byte("MZ\x00\x00"), []byte("...C:\\build\\stage2\\loader.pdb only")...) // $pdb alone
	if res, _ := rules.Scan(context.Background(), benign); len(res.Matches) != 0 {
		t.Fatal("one string alone must not fire a '2 of them' rule")
	}
}
