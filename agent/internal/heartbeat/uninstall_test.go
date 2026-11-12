package heartbeat

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/siem-platform/agent/internal/config"
)

func enrolledConfig(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "server: {url: \"https://siem.invalid\"}\nagent: {id: \"a1\", token: \"" + token + "\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func stubFetch(t *testing.T, hash string, err error) *int {
	t.Helper()
	calls := 0
	orig := fetchUninstallHash
	fetchUninstallHash = func(string, *config.Config) (string, error) { calls++; return hash, err }
	t.Cleanup(func() { fetchUninstallHash = orig })
	return &calls
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Deleting uninstall.sha256 used to turn the token check off. An enrolled
// agent now asks the server, and refuses when it can't.
func TestUninstallHashDeletedOnEnrolledAgentAsksTheServer(t *testing.T) {
	cfg := enrolledConfig(t, "agent-token")
	calls := stubFetch(t, hashOf("tok-123"), nil)

	if err := VerifyUninstallToken(cfg, "wrong"); !errors.Is(err, ErrUninstallRefused) {
		t.Fatalf("wrong token with the hash from the server: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("server asked %d times", *calls)
	}
	// stored again: the next check needs no server
	if err := VerifyUninstallToken(cfg, "tok-123"); err != nil {
		t.Fatalf("right token: %v", err)
	}
	if *calls != 1 {
		t.Fatal("the hash from the server must be kept")
	}
}

func TestUninstallHashDeletedAndServerUnreachableRefuses(t *testing.T) {
	cfg := enrolledConfig(t, "agent-token")
	stubFetch(t, "", errors.New("connection refused"))
	if err := VerifyUninstallToken(cfg, "anything"); !errors.Is(err, ErrUninstallUnverifiable) {
		t.Fatalf("got %v", err)
	}
	stubFetch(t, "short", nil) // an old server: no hash in the stopping reply
	if err := VerifyUninstallToken(cfg, "anything"); !errors.Is(err, ErrUninstallUnverifiable) {
		t.Fatalf("got %v", err)
	}
}

func TestUninstallCorruptedConfigRefuses(t *testing.T) {
	stubFetch(t, "", errors.New("must not be called"))
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("agent: [this is: not, a mapping\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyUninstallToken(path, ""); !errors.Is(err, ErrUninstallUnverifiable) {
		t.Fatalf("breaking the config must not turn the token check off: %v", err)
	}
}

func TestUninstallAgentDeletedOnServerIsAllowed(t *testing.T) {
	cfg := enrolledConfig(t, "agent-token")
	stubFetch(t, "", errAgentUnknown)
	if err := VerifyUninstallToken(cfg, ""); err != nil {
		t.Fatalf("an agent the server no longer knows must be removable: %v", err)
	}
}

func TestUninstallNeverEnrolledIsAllowed(t *testing.T) {
	calls := stubFetch(t, "", errors.New("must not be called"))
	cfg := enrolledConfig(t, "") // installed, never enrolled
	if err := VerifyUninstallToken(cfg, ""); err != nil {
		t.Fatalf("an agent that never enrolled has no token to check: %v", err)
	}
	if err := VerifyUninstallToken(filepath.Join(t.TempDir(), "none.yaml"), ""); err != nil {
		t.Fatalf("no config at all: %v", err)
	}
	if *calls != 0 {
		t.Fatal("no server call for an agent that never enrolled")
	}
}
