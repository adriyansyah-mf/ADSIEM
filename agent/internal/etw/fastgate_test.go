package etw

import "testing"

// I4: the fast decode is used only for known event versions, is checked
// against TDH on the first events, and is switched off for good on a mismatch.
func TestFastGate(t *testing.T) {
	g := newFastGate(Fast{ID: 16, Versions: []uint8{0, 1}, Verify: 3})
	if fast, check := g.plan(2); fast || check {
		t.Fatalf("unknown version 2: fast=%t check=%t, want TDH", fast, check)
	}
	for i := 0; i < 3; i++ {
		fast, check := g.plan(1)
		if !fast || !check {
			t.Fatalf("event %d: fast=%t check=%t, want a checked fast decode", i, fast, check)
		}
		g.result(0xABC, 0xABC, true)
	}
	if fast, check := g.plan(1); !fast || check {
		t.Fatalf("after 3 matches: fast=%t check=%t, want fast only", fast, check)
	}
	if v, m, off := g.stats(); v != 3 || m != 0 || off {
		t.Fatalf("stats = %d %d %t", v, m, off)
	}

	bad := newFastGate(Fast{ID: 16, Versions: []uint8{1}, Verify: 3})
	bad.plan(1)
	bad.result(0xABC, 0xDEF, true) // the layout is not what we thought
	if fast, _ := bad.plan(1); fast {
		t.Fatal("fast decode still used after a mismatch")
	}
	if _, m, off := bad.stats(); m != 1 || !off {
		t.Fatalf("mismatch not counted/disabled: %d %t", m, off)
	}
	// No versions listed: every version is fast (callers that know better list them).
	if fast, _ := newFastGate(Fast{ID: 16}).plan(7); !fast {
		t.Fatal("no version list")
	}
}
