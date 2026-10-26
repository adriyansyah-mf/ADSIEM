package prevent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

type fakeEngines struct{ applied []*Policy }

func (f *fakeEngines) apply(p *Policy) { f.applied = append(f.applied, p) }
func (f *fakeEngines) close()          {}

type fakeServer struct {
	hash  string
	rules []Rule
	sent  []string // loaded_hash of each request
}

func (s *fakeServer) PostContext(_ context.Context, path string, payload any) (*http.Response, error) {
	s.sent = append(s.sent, payload.(map[string]any)["loaded_hash"].(string))
	body := rulesResponse{Hash: s.hash, Rules: s.rules}
	if s.sent[len(s.sent)-1] == s.hash {
		body = rulesResponse{Hash: s.hash, Unchanged: true}
	}
	b, _ := json.Marshal(body)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func TestSyncAppliesOnlyChanges(t *testing.T) {
	eng := &fakeEngines{}
	m := &Manager{eng: eng, last: map[string]time.Time{}}
	srv := &fakeServer{hash: "h1", rules: []Rule{{Name: "shm", RuleType: TypeDir, Value: "/dev/shm", Action: ActionDetect}}}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := m.Sync(ctx, srv); err != nil {
			t.Fatal(err)
		}
	}
	if len(eng.applied) != 1 || len(eng.applied[0].Rules) != 1 || m.Hash() != "h1" {
		t.Fatalf("applied %d times, hash %q", len(eng.applied), m.Hash())
	}
	if srv.sent[0] != "" || srv.sent[1] != "h1" {
		t.Fatalf("loaded_hash sent: %q", srv.sent)
	}
	srv.hash, srv.rules = "", nil // every rule deleted on the server
	if err := m.Sync(ctx, srv); err != nil {
		t.Fatal(err)
	}
	if len(eng.applied) != 2 || len(eng.applied[1].Rules) != 0 {
		t.Fatal("an emptied rule set must be applied")
	}
}
