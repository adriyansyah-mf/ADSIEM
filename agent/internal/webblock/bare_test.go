package webblock

import (
	"reflect"
	"strings"
	"testing"
)

func TestRenderBlockBareDomains(t *testing.T) {
	got := RenderBlock([]string{"feed.example", "manual.example"}, true, map[string]bool{"feed.example": true})
	want := BlockBegin + "\n" +
		"127.84.0.1 feed.example\n::1 feed.example\n" +
		"127.84.0.1 manual.example\n::1 manual.example\n" +
		"127.84.0.1 www.manual.example\n::1 www.manual.example\n" + BlockEnd + "\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderBlockBareKeepsExplicitWWW(t *testing.T) {
	// a feed lists www.x.example itself: it still gets its own line
	got := RenderBlock([]string{"www.x.example"}, false, map[string]bool{"www.x.example": true})
	if !strings.Contains(got, "127.84.0.1 www.x.example\n") || strings.Contains(got, "www.www.") {
		t.Fatalf("got:\n%s", got)
	}
}

func TestApplyFeedDomainsGetNoWWW(t *testing.T) {
	c, h, _, _, _ := newCtl(t)
	l := listOf("g:1", "p", "manual.example", "alert.example")
	l.Entries["alert.example"] = Entry{Source: "alert"}
	for d, src := range map[string]string{"uh.example": "urlhaus", "pt.example": "phishtank", "odd.example": "something-new"} {
		l.Entries[d] = Entry{Source: src}
	}
	c.Apply(l)
	want := map[string]bool{"uh.example": true, "pt.example": true, "odd.example": true}
	if !reflect.DeepEqual(h.bare[0], want) {
		t.Fatalf("bare %v, want %v", h.bare[0], want)
	}
}

func TestApplyRewritesHostsWhenSourceChanges(t *testing.T) {
	c, h, _, _, _ := newCtl(t)
	l1 := listOf("g:1", "p", "x.example")
	l1.Entries["x.example"] = Entry{Source: "urlhaus"}
	c.Apply(l1)
	c.Apply(listOf("g:2", "p", "x.example")) // now manual: gains a www. line
	if len(h.applied) != 2 || len(h.bare[1]) != 0 {
		t.Fatalf("applies %d bare %v", len(h.applied), h.bare)
	}
}

func TestSelectedPrefersManualOverFeed(t *testing.T) {
	l := listOf("g:1", "p", "both.example")
	l.Policy.MaxEntries = 1
	l.Entries["feed.example"] = Entry{Source: "urlhaus"}
	if got := l.Selected(); len(got) != 1 || got[0] != "both.example" {
		t.Fatalf("selected %v", got)
	}
}
