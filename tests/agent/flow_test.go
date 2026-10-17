package agent_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/task"
)

type recordedUpdate struct {
	State  string           `json:"state"`
	Source string           `json:"source"`
	Rows   []map[string]any `json:"rows"`
	Logs   []struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"logs"`
	Error string `json:"error"`
}

// fakeServer records flow updates; cancelAfterRows makes it answer
// {"cancel": true} once that many rows have arrived (0 = never).
type fakeServer struct {
	mu              sync.Mutex
	updates         []recordedUpdate
	cancelAfterRows int
	rows            int
}

func (s *fakeServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Token") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/update") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var u recordedUpdate
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			t.Errorf("bad update body: %v", err)
		}
		s.mu.Lock()
		s.updates = append(s.updates, u)
		s.rows += len(u.Rows)
		cancel := s.cancelAfterRows > 0 && s.rows >= s.cancelAfterRows
		s.mu.Unlock()
		fmt.Fprintf(w, `{"cancel": %t}`, cancel)
	})
}

func (s *fakeServer) snapshot() []recordedUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedUpdate(nil), s.updates...)
}

func runFlow(t *testing.T, srv *fakeServer, plugins map[string]task.Plugin, req task.FlowRequest) []recordedUpdate {
	t.Helper()
	ts := httptest.NewServer(srv.handler(t))
	defer ts.Close()
	runner := task.NewFlowRunner(client.New(ts.URL, "tok"))
	if plugins != nil {
		runner.Plugins = plugins
	}
	runner.Start(req)
	deadline := time.Now().Add(10 * time.Second)
	for runner.Running() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("flow did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return srv.snapshot()
}

func counter(n int) task.Plugin {
	return func(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
		for i := 0; i < n; i++ {
			if err := emit(map[string]any{"N": i}); err != nil {
				return err
			}
		}
		return nil
	}
}

func final(updates []recordedUpdate) recordedUpdate {
	for i := len(updates) - 1; i >= 0; i-- {
		if s := updates[i].State; s != "" && s != "running" {
			return updates[i]
		}
	}
	return recordedUpdate{}
}

func rowsBySource(updates []recordedUpdate) map[string]int {
	out := map[string]int{}
	for _, u := range updates {
		out[u.Source] += len(u.Rows)
	}
	return out
}

func TestFlowStreamsRowsInBatchesAndFinishes(t *testing.T) {
	srv := &fakeServer{}
	updates := runFlow(t, srv, map[string]task.Plugin{"a": counter(1200), "b": counter(3)}, task.FlowRequest{
		ID: "f1", Artifact: "Test", Timeout: 5, MaxRows: 5000,
		Sources: []task.FlowSource{{Name: "A", Plugin: "a"}, {Name: "B", Plugin: "b"}},
	})
	if updates[0].State != "running" {
		t.Fatalf("first update should mark the flow running, got %+v", updates[0])
	}
	for _, u := range updates {
		if len(u.Rows) > 500 {
			t.Fatalf("batch of %d rows exceeds 500", len(u.Rows))
		}
	}
	if got := rowsBySource(updates); got["A"] != 1200 || got["B"] != 3 {
		t.Fatalf("rows per source = %v", got)
	}
	if f := final(updates); f.State != "finished" || f.Error != "" {
		t.Fatalf("final update = %+v", f)
	}
	var logs []string
	for _, u := range updates {
		for _, l := range u.Logs {
			logs = append(logs, l.Message)
		}
	}
	if !strings.Contains(strings.Join(logs, "\n"), "A: 1200 row(s) from a") {
		t.Fatalf("missing per-source log, got %q", logs)
	}
}

func TestFlowStopsAtMaxRows(t *testing.T) {
	srv := &fakeServer{}
	updates := runFlow(t, srv, map[string]task.Plugin{"a": counter(100000), "b": counter(5)}, task.FlowRequest{
		ID: "f2", Timeout: 5, MaxRows: 750,
		Sources: []task.FlowSource{{Name: "A", Plugin: "a"}, {Name: "B", Plugin: "b"}},
	})
	if got := rowsBySource(updates); got["A"] != 750 || got["B"] != 0 {
		t.Fatalf("rows per source = %v, want A=750 and B skipped", got)
	}
	if f := final(updates); f.State != "finished" {
		t.Fatalf("hitting the row limit should still finish, got %+v", f)
	}
}

func TestFlowTimesOut(t *testing.T) {
	block := func(ctx context.Context, _ map[string]any, _ func(map[string]any) error) error {
		<-ctx.Done()
		return ctx.Err()
	}
	srv := &fakeServer{}
	start := time.Now()
	updates := runFlow(t, srv, map[string]task.Plugin{"block": block}, task.FlowRequest{
		ID: "f3", Timeout: 1, Sources: []task.FlowSource{{Name: "S", Plugin: "block"}},
	})
	if f := final(updates); f.State != "error" || !strings.Contains(f.Error, "timed out after 1s") {
		t.Fatalf("final update = %+v", f)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout did not stop the flow promptly")
	}
}

func TestFlowAbandonsPluginThatIgnoresContext(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	// like a read() on /proc/kmsg: blocks and never looks at ctx
	ignore := func(_ context.Context, _ map[string]any, _ func(map[string]any) error) error {
		<-stuck
		return nil
	}
	srv := &fakeServer{}
	start := time.Now()
	updates := runFlow(t, srv, map[string]task.Plugin{"stuck": ignore}, task.FlowRequest{
		ID: "f6", Timeout: 1, Sources: []task.FlowSource{{Name: "S", Plugin: "stuck"}},
	})
	if f := final(updates); f.State != "error" || !strings.Contains(f.Error, "timed out after 1s") {
		t.Fatalf("final update = %+v", f)
	}
	if took := time.Since(start); took > 9*time.Second {
		t.Fatalf("abandoning took %s", took)
	}
}

func TestFlowStopsWhenServerSaysCancelled(t *testing.T) {
	srv := &fakeServer{cancelAfterRows: 500}
	updates := runFlow(t, srv, map[string]task.Plugin{"a": counter(100000)}, task.FlowRequest{
		ID: "f4", Timeout: 5, MaxRows: 100000, Sources: []task.FlowSource{{Name: "A", Plugin: "a"}},
	})
	if got := rowsBySource(updates)["A"]; got != 500 {
		t.Fatalf("agent kept sending after cancel: %d rows", got)
	}
	if f := final(updates); f.State != "" {
		t.Fatalf("a server-cancelled flow must not report a final state, got %+v", f)
	}
}

func TestFlowReportsUnknownPlugin(t *testing.T) {
	srv := &fakeServer{}
	updates := runFlow(t, srv, map[string]task.Plugin{"a": counter(2)}, task.FlowRequest{
		ID: "f5", Timeout: 5,
		Sources: []task.FlowSource{{Name: "X", Plugin: "nope"}, {Name: "A", Plugin: "a"}},
	})
	if got := rowsBySource(updates)["A"]; got != 2 {
		t.Fatalf("later sources should still run, got %d rows", got)
	}
	if f := final(updates); f.State != "error" || f.Error != "unknown plugin nope" {
		t.Fatalf("final update = %+v", f)
	}
}

func TestGlobAndHashPlugins(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "sub", "b.sh"), []byte("x"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "sub", "deep", "c.sh"), []byte("y"), 0o644))

	paths := func(globs ...string) []string {
		var got []string
		err := task.Plugins["glob"](context.Background(), map[string]any{"globs": toAny(globs)}, func(row map[string]any) error {
			got = append(got, strings.TrimPrefix(row["Path"].(string), dir))
			return nil
		})
		must(err)
		sort.Strings(got)
		return got
	}
	if got := paths(dir + "/*"); strings.Join(got, ",") != "/a.txt,/sub" {
		t.Fatalf("single-level glob = %v", got)
	}
	if got := paths(dir + "/**/*.sh"); strings.Join(got, ",") != "/sub/b.sh,/sub/deep/c.sh" {
		t.Fatalf("recursive glob = %v", got)
	}
	if got := paths(dir+"/a.txt", dir+"/*.txt"); strings.Join(got, ",") != "/a.txt" {
		t.Fatalf("literal path / dedupe = %v", got)
	}

	var row map[string]any
	must(task.Plugins["hash"](context.Background(), map[string]any{"globs": []any{dir + "/a.txt"}}, func(r map[string]any) error {
		row = r
		return nil
	}))
	sum := sha256.Sum256([]byte("hello"))
	if row["SHA256"] != hex.EncodeToString(sum[:]) || row["MD5"] != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("hash row = %v", row)
	}
}

func TestBuiltinPluginsRunOnThisHost(t *testing.T) {
	for _, name := range []string{"info", "pslist", "netstat", "users"} {
		n := 0
		err := task.Plugins[name](context.Background(), map[string]any{}, func(map[string]any) error {
			n++
			return nil
		})
		if err != nil || n == 0 {
			t.Errorf("%s: err=%v rows=%d", name, err, n)
		}
	}
}

func toAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
