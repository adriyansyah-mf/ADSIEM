package task

import "testing"

func TestHostIsolated(t *testing.T) {
	check := func(isolated, ok bool) func() (bool, bool) {
		return func() (bool, bool) { return isolated, ok }
	}
	failIfCalled := func() (bool, bool) {
		t.Fatal("netsh checked though the engine already says isolated")
		return false, false
	}
	cases := []struct {
		name   string
		engine bool
		native bool
		check  func() (bool, bool)
		want   *bool
	}{
		{"engine isolated", true, true, failIfCalled, ptr(true)},
		{"netsh rule in place (ransomguard, older agent)", false, true, check(true, true), ptr(true)},
		{"netsh rule absent", false, true, check(false, true), ptr(false)},
		{"netsh did not run: unknown", false, true, check(false, false), nil},
		{"linux, engine released", false, false, failIfCalled, ptr(false)},
	}
	for _, c := range cases {
		got := hostIsolated(c.engine, c.native, c.check)
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("%s: got %v, want %v", c.name, deref(got), deref(c.want))
		}
	}
}

func ptr(b bool) *bool { return &b }

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}
