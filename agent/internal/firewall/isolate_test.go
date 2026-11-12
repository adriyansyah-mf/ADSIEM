package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeIsolator records what the engine asks of a backend that can isolate.
type fakeIsolator struct {
	mu        sync.Mutex
	allow     []string // nil: not isolated
	isolates  int
	failNext  bool
	removed   []Rule
	unisolate int
}

func (f *fakeIsolator) Name() string          { return "fake" }
func (f *fakeIsolator) Ensure() error         { return nil }
func (f *fakeIsolator) Apply(Rule) error      { return nil }
func (f *fakeIsolator) List() ([]Rule, error) { return nil, nil }
func (f *fakeIsolator) Flush() error          { return nil }
func (f *fakeIsolator) Available() bool       { return true }
func (f *fakeIsolator) Remove(r Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, r)
	return nil
}

func (f *fakeIsolator) Isolate(allow []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return errors.New("backend refused")
	}
	f.isolates++
	f.allow = slices.Clone(allow)
	return nil
}

func (f *fakeIsolator) Unisolate() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unisolate++
	f.allow = nil
	return nil
}

func (f *fakeIsolator) current() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allow
}

// enforcingEngine: an engine on the fake backend (New can only pick real
// backends), with the server at 192.0.2.10 and no resolv.conf.
func enforcingEngine(t *testing.T, state string, opts Options) (*Engine, *fakeIsolator) {
	t.Helper()
	if opts.ServerURL == "" {
		opts.ServerURL = "https://192.0.2.10:8000"
	}
	opts.StatePath = state
	opts.Enabled = false // noop at construction, the fake goes in below
	e := New(opts)
	f := &fakeIsolator{}
	e.mu.Lock()
	e.backend = f
	e.dryRun = false
	e.degraded = ""
	e.mu.Unlock()
	e.guard.mu.Lock()
	e.guard.resolvConf = ""
	e.guard.mu.Unlock()
	t.Cleanup(func() {
		e.mu.Lock()
		e.stopIsolationMonitor()
		e.mu.Unlock()
	})
	return e, f
}

func TestIsolateAllowsServerLoopbackAndIPv6(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fw.json")
	e, f := enforcingEngine(t, state, Options{})
	res, err := e.Isolate()
	if err != nil {
		t.Fatal(err)
	}
	if res["isolated"] != true || res["direction"] != DirBoth || res["ipv6"] != true {
		t.Fatalf("result: %v", res)
	}
	for _, want := range []string{"192.0.2.10/32", "127.0.0.0/8", "::1/128", "fe80::/10"} {
		if !slices.Contains(f.current(), want) {
			t.Fatalf("%s not kept reachable: %v", want, f.current())
		}
	}
	if !e.Isolated() {
		t.Fatal("engine must report isolated")
	}
	if _, err := os.Stat(state + ".isolation.json"); err != nil {
		t.Fatalf("isolation must persist: %v", err)
	}
}

func TestIsolateOnNoopBackendIsAnError(t *testing.T) {
	e := New(Options{Enabled: false, ServerURL: "https://192.0.2.10", StatePath: filepath.Join(t.TempDir(), "fw.json")})
	if _, err := e.Isolate(); !errors.Is(err, ErrNotEnforcing) {
		t.Fatalf("a firewall that blocks nothing must not report isolation, got %v", err)
	}
	if e.Isolated() {
		t.Fatal("not isolated")
	}
}

func TestIsolateBackendFailureLeavesHostNotIsolated(t *testing.T) {
	e, f := enforcingEngine(t, filepath.Join(t.TempDir(), "fw.json"), Options{})
	f.failNext = true
	if _, err := e.Isolate(); err == nil {
		t.Fatal("backend failure must surface")
	}
	if e.Isolated() {
		t.Fatal("a failed isolation must not be recorded")
	}
}

func TestUnisolateReleasesAndForgets(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fw.json")
	e, f := enforcingEngine(t, state, Options{})
	if _, err := e.Isolate(); err != nil {
		t.Fatal(err)
	}
	if err := e.Unisolate(); err != nil {
		t.Fatal(err)
	}
	if f.current() != nil || e.Isolated() {
		t.Fatal("still isolated")
	}
	if _, err := os.Stat(state + ".isolation.json"); !os.IsNotExist(err) {
		t.Fatalf("state must be removed, got %v", err)
	}
	// unisolate with nothing recorded (state lost, reinstall) still clears the backend
	if err := e.Unisolate(); err != nil || f.unisolate != 2 {
		t.Fatalf("unisolate must always remove the backend's isolation: err=%v calls=%d", err, f.unisolate)
	}
}

func TestIsolationReleasedWhenServerUnreachable(t *testing.T) {
	var mu sync.Mutex
	last := time.Time{}
	contact := func() time.Time { mu.Lock(); defer mu.Unlock(); return last }
	e, f := enforcingEngine(t, filepath.Join(t.TempDir(), "fw.json"),
		Options{LastContact: contact, ReleaseAfterOffline: 10 * time.Minute})
	if _, err := e.Isolate(); err != nil {
		t.Fatal(err)
	}
	start := e.isolatedAt

	// no contact since isolating, but not for long enough yet
	e.isolationTick(start.Add(9 * time.Minute))
	if !e.Isolated() {
		t.Fatal("released too early")
	}
	// the server answered at +8m: the clock restarts from there
	mu.Lock()
	last = start.Add(8 * time.Minute)
	mu.Unlock()
	e.isolationTick(start.Add(17 * time.Minute))
	if !e.Isolated() {
		t.Fatal("a recent contact must keep the isolation")
	}
	e.isolationTick(start.Add(19 * time.Minute))
	if e.Isolated() || f.current() != nil {
		t.Fatal("server unreachable past the limit: the host must be released")
	}
}

func TestIsolationNeverReleasedWhenDisabled(t *testing.T) {
	e, _ := enforcingEngine(t, filepath.Join(t.TempDir(), "fw.json"),
		Options{LastContact: func() time.Time { return time.Time{} }, ReleaseAfterOffline: -1})
	if _, err := e.Isolate(); err != nil {
		t.Fatal(err)
	}
	e.isolationTick(e.isolatedAt.Add(1000 * time.Hour))
	if !e.Isolated() {
		t.Fatal("a negative ReleaseAfterOffline must never release")
	}
}

func TestIsolationFollowsTheServersNewAddress(t *testing.T) {
	addr := "192.0.2.10"
	var mu sync.Mutex
	orig := lookupHost
	lookupHost = func(string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if addr == "" {
			return nil, errors.New("no such host")
		}
		return []string{addr}, nil
	}
	t.Cleanup(func() { lookupHost = orig })

	e, f := enforcingEngine(t, filepath.Join(t.TempDir(), "fw.json"),
		Options{ServerURL: "https://siem.example:8000", ReleaseAfterOffline: -1})
	if _, err := e.Isolate(); err != nil {
		t.Fatal(err)
	}
	// DNS fails: the last good address stays allowed
	mu.Lock()
	addr = ""
	mu.Unlock()
	e.isolationTick(time.Now())
	if !slices.Contains(f.current(), "192.0.2.10/32") {
		t.Fatalf("a failed lookup must keep the server: %v", f.current())
	}
	// the server moved: the allow list follows
	mu.Lock()
	addr = "198.51.100.7"
	mu.Unlock()
	e.isolationTick(time.Now())
	if !slices.Contains(f.current(), "198.51.100.7/32") || slices.Contains(f.current(), "192.0.2.10/32") {
		t.Fatalf("allow list must follow the server: %v", f.current())
	}
}

func TestIsolationSurvivesARestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fw.json")
	e, _ := enforcingEngine(t, state, Options{})
	if _, err := e.Isolate(); err != nil {
		t.Fatal(err)
	}
	since := e.isolation.Since

	e2, f2 := enforcingEngine(t, state, Options{})
	e2.restoreIsolation(false) // New ran it on the noop backend; again on the fake
	if !e2.Isolated() || !slices.Contains(f2.current(), "192.0.2.10/32") {
		t.Fatalf("isolation not restored: %v", f2.current())
	}
	if !e2.isolation.Since.Equal(since) {
		t.Fatal("the isolation keeps its original start time")
	}
}

func TestLegacyIsolationRulesAreMigrated(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fw.json")
	old := `[{"id":"iso","action":"block","cidr":"0.0.0.0/0","direction":"in","reason":"isolate_host"},
	{"id":"keep","action":"block","cidr":"198.51.100.20","direction":"in","reason":"local:analyst"}]`
	if err := os.WriteFile(state, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(Options{Enabled: false, ServerURL: "https://192.0.2.10", StatePath: state})
	for _, r := range e.List() {
		if r.Reason == "isolate_host" {
			t.Fatal("the old 0.0.0.0/0 inbound block must not be replayed")
		}
	}
	if len(e.List()) != 1 {
		t.Fatalf("other rules are kept: %v", e.List())
	}
}

func TestSyncLeavesIsolationAlone(t *testing.T) {
	e, f := enforcingEngine(t, filepath.Join(t.TempDir(), "fw.json"), Options{})
	if _, err := e.Isolate(); err != nil {
		t.Fatal(err)
	}
	e.Sync(nil) // the server has no rules for this agent
	if !e.Isolated() || f.current() == nil || f.unisolate != 0 {
		t.Fatal("a server rule sync must not touch the isolation")
	}
}

func TestFailedRestoreIsRetried(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fw.json")
	e, _ := enforcingEngine(t, state, Options{ReleaseAfterOffline: -1})
	if _, err := e.Isolate(); err != nil {
		t.Fatal(err)
	}
	e2, f2 := enforcingEngine(t, state, Options{ReleaseAfterOffline: -1})
	f2.failNext = true // nft/netsh not ready at boot
	e2.restoreIsolation(false)
	if f2.current() != nil || !e2.Isolated() || !e2.isolation.pending {
		t.Fatal("a failed restore must stay wanted (pending), not be dropped")
	}
	e2.isolationTick(time.Now())
	if !slices.Contains(f2.current(), "192.0.2.10/32") || e2.isolation.pending {
		t.Fatalf("the monitor must re-apply it: %v", f2.current())
	}
}

func TestLegacyIsolationWithoutServerWaits(t *testing.T) {
	orig := lookupHost
	lookupHost = func(string) ([]string, error) { return nil, errors.New("offline") }
	t.Cleanup(func() { lookupHost = orig })
	e, f := enforcingEngine(t, filepath.Join(t.TempDir(), "fw.json"),
		Options{ServerURL: "https://siem.example", ReleaseAfterOffline: -1})
	e.restoreIsolation(true) // an old block-rule isolation, no address known
	if f.current() != nil || !e.isolation.pending {
		t.Fatal("no server address: isolating would strand the host, it must wait")
	}
	lookupHost = func(string) ([]string, error) { return []string{"192.0.2.44"}, nil }
	e.isolationTick(time.Now())
	if !slices.Contains(f.current(), "192.0.2.44/32") {
		t.Fatalf("applied once the server resolves: %v", f.current())
	}
}
