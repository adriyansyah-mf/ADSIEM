package heartbeat

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
)

type LogSource struct {
	Path      string `json:"path"`
	LogType   string `json:"log_type"`
	IsEnabled bool   `json:"is_enabled"`
}

type AgentTask struct {
	ID       string         `json:"id"`
	TaskType string         `json:"task_type"`
	Params   map[string]any `json:"params"`
}

type HeartbeatRequest struct {
	AgentID       string     `json:"agent_id"`
	Status        string     `json:"status"`
	Version       string     `json:"version"`
	BufferDropped int64      `json:"buffer_dropped"`
	Reason        string     `json:"reason,omitempty"` // with status "stopping": service_stop | system_shutdown
	Integrity     *Integrity `json:"integrity,omitempty"`
	// One random id per agent process and a counter per heartbeat: the server
	// spots a second sender using this agent's token (sessions interleaving) or
	// a replayed heartbeat (a sequence number going back).
	Session string `json:"session,omitempty"`
	Seq     int64  `json:"seq,omitempty"`
	// Durable evidence mode only; legacy agents omit it and the server shows
	// their evidence delivery as not reported.
	EvidenceHealth any `json:"evidence_health,omitempty"`
}

// Session identifies this agent process in its heartbeats.
var Session = newSession()

var seq atomic.Int64

func newSession() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// UninstallHashPath is where the server's uninstall-token hash is kept
// (next to the config); `siem-agent -verify-uninstall-token` checks against it.
func UninstallHashPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "uninstall.sha256")
}

// storeUninstallHash writes the hash the server sent, when it changed.
func storeUninstallHash(hash string) {
	if ConfigPath == "" || len(hash) != 64 {
		return
	}
	path := UninstallHashPath(ConfigPath)
	if old, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(old)) == hash {
		return
	}
	if err := os.WriteFile(path, []byte(hash+"\n"), 0o600); err != nil {
		slog.Warn("could not store the uninstall token hash", "err", err)
	}
}

// Integrity is what the server compares against the agent's baseline: a
// binary or config that changes without a version change is tampering.
type Integrity struct {
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
}

type FirewallRule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr"`
	Proto      string `json:"proto"`
	Port       int    `json:"port"`
	Direction  string `json:"direction"`
	TTLSeconds int    `json:"ttl_seconds"`
	Reason     string `json:"reason"`
}

// AgentVersion is sent on every heartbeat; main sets it from its -ldflags
// version. The server uses it to tell which agents support live-response flows.
var AgentVersion = "dev"

// ConfigPath is the config file whose hash goes in each heartbeat; main sets it.
var ConfigPath string

// integrityEvery: hashing reads the whole binary, so not on every beat.
const integrityEvery = 5 * time.Minute

func sha256File(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func currentIntegrity() *Integrity {
	exe, err := os.Executable()
	if err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
	}
	in := Integrity{ConfigSHA256: sha256File(ConfigPath)}
	if err == nil {
		in.BinarySHA256 = sha256File(exe)
	}
	if in == (Integrity{}) {
		return nil
	}
	return &in
}

// SendStopping tells the server this agent is stopping on purpose, so it can
// tell a stopped service (alert) from a host shutting down or a lost network.
func SendStopping(cfg *config.Config, c *client.Client, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.PostContext(ctx, "/api/ingest/heartbeat", HeartbeatRequest{
		AgentID: cfg.Agent.ID, Status: "stopping", Version: AgentVersion, Reason: reason,
		Session: Session, Seq: seq.Add(1),
	})
	if err != nil {
		slog.Warn("could not report stopping", "err", err)
		return
	}
	resp.Body.Close()
}

type HeartbeatResponse struct {
	ConfigHash string         `json:"config_hash"`
	LogSources []LogSource    `json:"log_sources"`
	FimPaths   []string       `json:"fim_paths"`
	Tasks      []AgentTask    `json:"tasks"`
	Firewall   []FirewallRule `json:"firewall"`
	// SHA-256 of this agent's uninstall token (server-side secret); kept
	// locally so package removal can be refused without it.
	UninstallTokenSHA256 string `json:"uninstall_token_sha256"`
	// Durable ingest protocols the server accepts right now; [2] only while its
	// inbox is enabled and healthy (server-api check_evidence_durability).
	EvidenceProtocols []int `json:"evidence_protocols"`
	// >0: the server takes this many events per POST /api/ingest/v2/logs.
	EvidenceBatchMax int `json:"evidence_batch_max"`
	// Version of the enabled YARA rule set ("" when there is none); the
	// rules themselves are fetched from /api/ingest/yara-rules on change.
	YaraRulesHash string `json:"yara_rules_hash"`
}

var (
	evidenceV2       atomic.Bool
	evidenceBatchMax atomic.Int64
)

// EvidenceHealth, when set (durable evidence mode), returns the journal's
// cumulative health for the heartbeat. Counters live in the journal, so a
// failed heartbeat loses nothing: the next one reports the same totals.
var EvidenceHealth func() any

// SupportsEvidenceV2 reports whether the last successful heartbeat advertised
// durable ingest protocol 2. The evidence sender sends nothing until it does.
func SupportsEvidenceV2() bool { return evidenceV2.Load() }

// EvidenceBatchMax is the batch size the last successful heartbeat advertised
// for durable ingest; 0 (older server, or protocol 2 unavailable) means one
// event per request.
func EvidenceBatchMax() int {
	if !evidenceV2.Load() {
		return 0
	}
	return int(evidenceBatchMax.Load())
}

func storeEvidenceProtocols(protocols []int, batchMax int) {
	supported := false
	for _, p := range protocols {
		supported = supported || p == 2
	}
	evidenceBatchMax.Store(int64(max(batchMax, 0)))
	if evidenceV2.Swap(supported) != supported {
		slog.Info("durable evidence protocol", "supported", supported)
	}
}

// Loop sends heartbeats every interval.
// Calls onConfig when config hash changes, calls onTasks for every heartbeat with tasks.
func Loop(
	cfg *config.Config,
	buf *buffer.Buffer,
	c *client.Client,
	onConfig func(HeartbeatResponse),
	onTasks func([]AgentTask),
) {
	lastHash := ""
	interval := time.Duration(cfg.Server.HeartbeatInterval) * time.Second
	var integrity *Integrity
	var hashedAt time.Time

	for {
		if integrity == nil || time.Since(hashedAt) >= integrityEvery {
			integrity, hashedAt = currentIntegrity(), time.Now()
		}
		dropped := buf.ResetDropped()
		payload := HeartbeatRequest{
			AgentID:       cfg.Agent.ID,
			Status:        "online",
			Version:       AgentVersion,
			BufferDropped: dropped,
			Integrity:     integrity,
			Session:       Session,
			Seq:           seq.Add(1),
		}
		if EvidenceHealth != nil {
			payload.EvidenceHealth = EvidenceHealth()
		}
		resp, err := c.Post("/api/ingest/heartbeat", payload)
		if err != nil {
			slog.Error("heartbeat failed", "err", err)
			time.Sleep(interval)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			var hbResp HeartbeatResponse
			if err := json.Unmarshal(body, &hbResp); err == nil {
				storeUninstallHash(hbResp.UninstallTokenSHA256)
				storeEvidenceProtocols(hbResp.EvidenceProtocols, hbResp.EvidenceBatchMax)
				if hbResp.ConfigHash != lastHash {
					slog.Info("config updated", "hash", hbResp.ConfigHash)
					lastHash = hbResp.ConfigHash
					onConfig(hbResp)
				}
				if len(hbResp.Tasks) > 0 {
					slog.Info("tasks received", "count", len(hbResp.Tasks))
					onTasks(hbResp.Tasks)
				}
			}
		} else {
			slog.Warn("heartbeat non-200", "status", resp.StatusCode)
		}
		time.Sleep(interval)
	}
}

// ErrUninstallRefused: a token is required (the server provisioned one) and
// the given one is missing or wrong.
var ErrUninstallRefused = errors.New("uninstall refused: wrong or missing uninstall token " +
	"(Agents page → agent → Uninstall token)")

// VerifyUninstallToken is what the package removal hooks call. With no hash
// provisioned yet (never reached the server) removal is allowed.
func VerifyUninstallToken(configPath, token string) error {
	want, err := os.ReadFile(UninstallHashPath(configPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(token)))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(got[:])), []byte(strings.TrimSpace(string(want)))) != 1 {
		return ErrUninstallRefused
	}
	return nil
}
