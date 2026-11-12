package heartbeat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/client"
)

// The server rotates the token over the heartbeat: the agent says it can
// (token_rotation: 1), uses the new token on the next request, and keeps it
// beside config.yaml (not in it: that would read as tampering). Loop calls
// storeAgentToken with a non-empty HeartbeatResponse.AgentToken; it isn't run
// here because it can't be stopped (a leaked loop races with other tests).
func TestRotatedTokenIsUsedAndKeptOutsideTheConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("agent:\n  token: enroll-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, oldBasis := ConfigPath, TokenBasis
	ConfigPath, TokenBasis = cfgPath, TokenBasisOf("enroll-token")
	defer func() { ConfigPath, TokenBasis = old, oldBasis }()

	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = append(sent, r.Header.Get("X-Agent-Token"))
	}))
	defer srv.Close()
	c := client.New(srv.URL, "enroll-token")

	storeAgentToken(c, "rotated-token")
	resp, err := c.Post("/api/ingest/heartbeat", HeartbeatRequest{AgentID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if c.Token() != "rotated-token" || len(sent) != 1 || sent[0] != "rotated-token" {
		t.Fatalf("client token=%q sent=%v", c.Token(), sent)
	}
	if got := LoadStoredToken(cfgPath, TokenBasisOf("enroll-token")); got != "rotated-token" {
		t.Fatalf("stored token = %q", got)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(TokenPath(cfgPath)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("token file mode = %v, %v", info.Mode().Perm(), err)
		}
	}
	if data, _ := os.ReadFile(cfgPath); string(data) != "agent:\n  token: enroll-token\n" {
		t.Fatalf("config.yaml was rewritten: %q", data)
	}
}

func TestHeartbeatAnnouncesTokenRotation(t *testing.T) {
	data, err := json.Marshal(HeartbeatRequest{AgentID: "a", TokenRotation: 1})
	if err != nil || !strings.Contains(string(data), `"token_rotation":1`) {
		t.Fatalf("%s %v", data, err)
	}
	var resp HeartbeatResponse
	if err := json.Unmarshal([]byte(`{"agent_token":"t2","config_hash":"x"}`), &resp); err != nil || resp.AgentToken != "t2" {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestStoredTokenLoadAndRemove(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	basis := TokenBasisOf("enroll-token")
	if LoadStoredToken(cfgPath, basis) != "" || LoadStoredToken("", basis) != "" {
		t.Fatal("no stored token expected")
	}
	if err := os.WriteFile(TokenPath(cfgPath), []byte("tok\n"+basis+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadStoredToken(cfgPath, basis); got != "tok" {
		t.Fatalf("got %q", got)
	}
	RemoveStoredToken(cfgPath)
	RemoveStoredToken(cfgPath) // already gone: no error
	if LoadStoredToken(cfgPath, basis) != "" {
		t.Fatal("token not removed")
	}
}

// config.yaml got a different token (edited, reinstalled with the old config
// dir left behind): a rotated token stored for the old one must not override
// it, or the agent is locked out for good.
func TestStoredTokenForAnotherConfigTokenIsDropped(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	for _, content := range []string{"tok\n" + TokenBasisOf("old-config-token") + "\n", "tok\n"} {
		if err := os.WriteFile(TokenPath(cfgPath), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := LoadStoredToken(cfgPath, TokenBasisOf("new-config-token")); got != "" {
			t.Fatalf("stale token used: %q", got)
		}
		if _, err := os.Stat(TokenPath(cfgPath)); !os.IsNotExist(err) {
			t.Fatal("stale token file not removed")
		}
	}
}
