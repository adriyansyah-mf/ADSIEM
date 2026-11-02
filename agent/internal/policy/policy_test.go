package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExclusionKinds(t *testing.T) {
	s := Settings{Exclusions: []Exclusion{
		{Kind: "image", Value: "veeam.exe", Scopes: []string{ScopeRansomware}},
		{Kind: "image", Value: "/usr/bin/restic", Scopes: []string{ScopeRansomware}},
		{Kind: "path_prefix", Value: "/opt/build/", Scopes: []string{ScopeYara, ScopeMalware}},
		{Kind: "sha256", Value: strings.Repeat("ab", 32), Scopes: []string{ScopeMalware}},
		{Kind: "command_line", Value: "--nightly", Scopes: []string{ScopePrevention}},
	}}
	cases := []struct {
		scope string
		m     Match
		want  bool
	}{
		{ScopeRansomware, Match{Image: `C:\Program Files\Veeam\VEEAM.EXE`}, true},
		{ScopeRansomware, Match{Image: "/usr/bin/restic"}, true},
		{ScopeRansomware, Match{Image: "/tmp/restic"}, false},
		{ScopeYara, Match{Path: "/opt/build/out/a.so"}, true},
		{ScopeYara, Match{Path: "/opt/builder/a.so"}, false},
		{ScopePrevention, Match{Path: "/opt/build/a"}, false}, // other scope
		{ScopeMalware, Match{SHA256: strings.Repeat("AB", 32)}, true},
		{ScopePrevention, Match{CommandLine: "backup --NIGHTLY"}, true},
		{ScopeMalware, Match{}, false},
	}
	for i, c := range cases {
		if got := s.Excluded(c.scope, c.m); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
	if len(s.For(ScopeMalware)) != 2 || len(s.For(ScopeRansomware)) != 2 {
		t.Fatal("For filters by scope")
	}
	if runtime.GOOS == "windows" && !s.Excluded(ScopeYara, Match{Path: `/OPT/build/x`}) {
		t.Fatal("paths fold case on Windows")
	}
}

type server struct {
	body Policy
	n    int
}

func (s *server) PostContext(_ context.Context, path string, _ any) (*http.Response, error) {
	s.n++
	b, _ := json.Marshal(s.body)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func TestStoreSyncSaveAndChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	st := Open(path)
	if !st.Current().Settings.PreventionEnabled || st.Current().Settings.RansomwareMode != "stop" {
		t.Fatal("default: everything on")
	}
	var seen []string
	st.OnChange(func(p *Policy) { seen = append(seen, p.Version) })
	srv := &server{body: Policy{Group: "servers", Version: "v1", Settings: Settings{YaraOnAccess: false,
		RansomwareMode: "report", Exclusions: []Exclusion{{Kind: "image", Value: "x", Scopes: []string{ScopeYara}}}}}}
	st.Want("") // older server: nothing to do
	if st.needed() {
		t.Fatal("no version, no fetch")
	}
	st.Want("v1")
	if !st.needed() {
		t.Fatal("new version wanted")
	}
	if err := st.Sync(context.Background(), srv); err != nil {
		t.Fatal(err)
	}
	if st.needed() || st.Current().Settings.RansomwareMode != "report" || strings.Join(seen, ",") != ",v1" {
		t.Fatalf("after sync: %+v seen=%v", st.Current(), seen)
	}
	if again := Open(path).Current(); again.Version != "v1" || again.Group != "servers" || len(again.Settings.Exclusions) != 1 {
		t.Fatalf("not saved: %+v", again)
	}
}
