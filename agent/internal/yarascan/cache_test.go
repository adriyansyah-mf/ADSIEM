package yarascan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCachedRulesLoadedAtStart(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "yara_rules.json")
	srv := &fakeServer{hash: "v1", rules: []Rule{{ID: "1", Name: "pack", Content: evilRule, Revision: "r1"}}}

	first := New(Options{Push: func(string, string) {}, CacheFile: cache})
	if err := first.Sync(context.Background(), srv, "v1"); err != nil {
		t.Fatal(err)
	}

	// restart with the server down: the cached set is loaded by New
	srv.set(true)
	second := New(Options{Push: func(string, string) {}, CacheFile: cache})
	rules, hash := second.current()
	if hash != "v1" || rules == nil || rules.Len() != 1 {
		t.Fatalf("cached rules not loaded: hash %q", hash)
	}
	// the heartbeat advertises the same hash: no fetch needed
	before := srv.count()
	if err := second.Sync(context.Background(), srv, "v1"); err != nil || srv.count() != before {
		t.Fatalf("no fetch expected, err %v", err)
	}

	// every rule deleted on the server: the cache goes too
	if err := second.Sync(context.Background(), srv, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("cache must be removed with the rules, got %v", err)
	}
}
