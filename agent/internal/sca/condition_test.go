package sca

import "testing"

func TestFoldAllSkippedIsNotApplicable(t *testing.T) {
	status, _ := fold("all", []ruleEval{{evalSkip, "a"}, {evalSkip, "b"}})
	if status != StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", status)
	}
}

func TestFoldAll(t *testing.T) {
	if s, _ := fold("all", []ruleEval{{evalPass, "a"}, {evalPass, "b"}}); s != StatusPass {
		t.Fatalf("expected pass, got %s", s)
	}
	if s, _ := fold("all", []ruleEval{{evalPass, "a"}, {evalFail, "b"}}); s != StatusFail {
		t.Fatalf("expected fail, got %s", s)
	}
	// A skip mixed with passes doesn't drag the result down.
	if s, _ := fold("all", []ruleEval{{evalPass, "a"}, {evalSkip, "b"}}); s != StatusPass {
		t.Fatalf("expected pass (skip excluded from vote), got %s", s)
	}
}

func TestFoldAny(t *testing.T) {
	if s, _ := fold("any", []ruleEval{{evalFail, "a"}, {evalPass, "b"}}); s != StatusPass {
		t.Fatalf("expected pass, got %s", s)
	}
	if s, _ := fold("any", []ruleEval{{evalFail, "a"}, {evalFail, "b"}}); s != StatusFail {
		t.Fatalf("expected fail, got %s", s)
	}
	if s, _ := fold("any", []ruleEval{{evalSkip, "a"}, {evalSkip, "b"}}); s != StatusNotApplicable {
		t.Fatalf("expected not_applicable, got %s", s)
	}
}

func TestFoldNone(t *testing.T) {
	if s, _ := fold("none", []ruleEval{{evalFail, "a"}, {evalFail, "b"}}); s != StatusPass {
		t.Fatalf("expected pass (none matched), got %s", s)
	}
	if s, _ := fold("none", []ruleEval{{evalPass, "a"}}); s != StatusFail {
		t.Fatalf("expected fail (one matched), got %s", s)
	}
}

func TestFoldDefaultsToAll(t *testing.T) {
	if s, _ := fold("", []ruleEval{{evalPass, "a"}, {evalFail, "b"}}); s != StatusFail {
		t.Fatalf("expected fail (empty condition defaults to all), got %s", s)
	}
}
