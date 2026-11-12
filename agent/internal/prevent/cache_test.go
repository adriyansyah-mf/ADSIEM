package prevent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The rules the server sent last are enforced at the next start, before the
// server answers (it may never: the host is offline, or the server is down).
func TestCachedRulesEnforcedAtStart(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "prevention_rules.json")
	dir := t.TempDir()
	srv := &fakeServer{hash: "h1", rules: []Rule{{Name: "tmp", RuleType: TypeDir, Value: dir, Action: ActionBlock}}}

	first := &Manager{eng: &fakeEngines{}, last: map[string]time.Time{}, opts: Options{CacheFile: cache}}
	if err := first.Sync(context.Background(), srv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("a successful sync must cache the rules: %v", err)
	}

	// restart, server unreachable
	eng := &fakeEngines{}
	second := &Manager{eng: eng, last: map[string]time.Time{}, opts: Options{CacheFile: cache}}
	second.loadCache()
	if second.Hash() != "h1" || len(eng.applied) != 1 || len(eng.applied[0].Rules) != 1 || !eng.applied[0].Rules[0].block {
		t.Fatalf("cached blocking rule not enforced at start: hash %q, applied %d", second.Hash(), len(eng.applied))
	}

	// the server then answers "unchanged": nothing re-applied, nothing lost
	if err := second.Sync(context.Background(), srv); err != nil {
		t.Fatal(err)
	}
	if srv.sent[len(srv.sent)-1] != "h1" || len(eng.applied) != 1 {
		t.Fatalf("the cached hash must be sent as loaded_hash: %q", srv.sent)
	}
}

func TestDamagedCacheIsIgnored(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "prevention_rules.json")
	if err := os.WriteFile(cache, []byte(`{"hash":"h1","checksum":"00","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := &fakeEngines{}
	m := &Manager{eng: eng, last: map[string]time.Time{}, opts: Options{CacheFile: cache}}
	m.loadCache()
	if m.Hash() != "" || len(eng.applied) != 0 {
		t.Fatal("a cache that fails its checksum must not be applied")
	}
}
