package heartbeat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeartbeatEvidenceProtocolFollowsTheLatestResponse(t *testing.T) {
	defer storeEvidenceProtocols(nil)
	for _, c := range []struct {
		protocols []int
		want      bool
	}{
		{[]int{2}, true},
		{nil, false}, // the server disabled its inbox: stop sending v2
		{[]int{1, 2, 3}, true},
		{[]int{1, 3}, false},
	} {
		storeEvidenceProtocols(c.protocols)
		if got := SupportsEvidenceV2(); got != c.want {
			t.Fatalf("protocols %v: supported=%v", c.protocols, got)
		}
	}
}

func TestLegacyHeartbeatOmitsEvidenceHealth(t *testing.T) {
	b, err := json.Marshal(HeartbeatRequest{AgentID: "a", Status: "online"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "evidence_health") {
		t.Fatalf("legacy heartbeat carries evidence_health: %s", b)
	}
	b, _ = json.Marshal(HeartbeatRequest{AgentID: "a", EvidenceHealth: map[string]int{"version": 1}})
	if !strings.Contains(string(b), `"evidence_health":{"version":1}`) {
		t.Fatalf("durable heartbeat lost evidence_health: %s", b)
	}
}

func TestIntegrityHashesBinaryAndConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("server: {url: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ConfigPath = cfg
	defer func() { ConfigPath = "" }()

	first := currentIntegrity()
	if first == nil || len(first.BinarySHA256) != 64 || len(first.ConfigSHA256) != 64 {
		t.Fatalf("integrity %+v", first)
	}
	if err := os.WriteFile(cfg, []byte("server: {url: y}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := currentIntegrity()
	if second.ConfigSHA256 == first.ConfigSHA256 || second.BinarySHA256 != first.BinarySHA256 {
		t.Fatalf("an edited config must change only the config hash: %+v → %+v", first, second)
	}

	// the uninstall token hash from the server: stored once, then enforced
	if err := VerifyUninstallToken(cfg, ""); err != nil {
		t.Fatalf("nothing provisioned yet must allow removal: %v", err)
	}
	sum := sha256.Sum256([]byte("tok-123"))
	storeUninstallHash(hex.EncodeToString(sum[:]))
	if err := VerifyUninstallToken(cfg, "wrong"); err != ErrUninstallRefused {
		t.Fatalf("wrong token: %v", err)
	}
	if err := VerifyUninstallToken(cfg, ""); err != ErrUninstallRefused {
		t.Fatalf("missing token: %v", err)
	}
	if err := VerifyUninstallToken(cfg, " tok-123\n"); err != nil {
		t.Fatalf("right token: %v", err)
	}

	ConfigPath = filepath.Join(t.TempDir(), "missing.yaml")
	if in := currentIntegrity(); in.ConfigSHA256 != "" || in.BinarySHA256 == "" {
		t.Fatalf("a missing config hashes as empty: %+v", in)
	}
}
