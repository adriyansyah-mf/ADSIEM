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
	"github.com/siem-platform/agent/internal/update"
	"gopkg.in/yaml.v3"
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
	// Web protection state (hosts block, CA, page server); omitted until the
	// agent wires WebBlockHealth.
	WebBlockHealth any `json:"web_block_health,omitempty"`
	// Self-update status (agents >= 1.9.0); the server offers updates only to
	// agents reporting it.
	Update *update.Status `json:"update,omitempty"`
	// TokenRotation = 1: this agent stores a token handed back in
	// HeartbeatResponse.AgentToken (servers rotate only agents that say so).
	TokenRotation int `json:"token_rotation,omitempty"`
}

// Updater, when set, reports its status on every heartbeat and receives the
// server's update offers.
var Updater *update.Updater

func updateStatus() *update.Status {
	if Updater == nil {
		return nil
	}
	s := Updater.Status()
	return &s
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

// TokenPath is where a rotated agent token is kept: next to the config, not in
// it. Rewriting config.yaml would change config_sha256, which the server reads
// as tampering.
func TokenPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "agent.token")
}

// TokenBasis fingerprints the token in config.yaml at startup. A rotated
// token is stored with it and used only while config.yaml still holds that
// token: when the config gets a new one (edited, reinstalled), a stored token
// from before would otherwise override it and lock the agent out.
var TokenBasis string

// TokenBasisOf is the fingerprint of a config token.
func TokenBasisOf(configToken string) string {
	sum := sha256.Sum256([]byte(configToken))
	return hex.EncodeToString(sum[:])
}

// LoadStoredToken is the last token the server rotated to, or "" when there
// is none or it belongs to another config token (it is then removed).
func LoadStoredToken(configPath, basis string) string {
	if configPath == "" {
		return ""
	}
	data, err := os.ReadFile(TokenPath(configPath))
	if err != nil {
		return ""
	}
	lines := strings.Fields(string(data))
	if len(lines) != 2 || lines[1] != basis {
		slog.Warn("ignoring a stored agent token issued for a different config token")
		RemoveStoredToken(configPath)
		return ""
	}
	return lines[0]
}

// RemoveStoredToken drops a rotated token, after a fresh enrollment replaced it.
func RemoveStoredToken(configPath string) {
	if configPath == "" {
		return
	}
	if err := os.Remove(TokenPath(configPath)); err != nil && !os.IsNotExist(err) {
		slog.Warn("could not remove the stored agent token", "err", err)
	}
}

// storeAgentToken keeps a rotated token across restarts (temp file + rename,
// 0600). It is applied to the client either way: the server still accepts the
// previous token during its grace, so a failed write is not fatal.
func storeAgentToken(c *client.Client, token string) {
	c.SetToken(token)
	if ConfigPath == "" {
		return
	}
	path := TokenPath(ConfigPath)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(token+"\n"+TokenBasis+"\n"), 0o600); err != nil {
		slog.Warn("could not store the rotated agent token", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		slog.Warn("could not store the rotated agent token", "err", err)
		_ = os.Remove(tmp)
		return
	}
	slog.Info("agent token rotated")
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

// Unreadable is sent instead of a hash once a file could not be hashed on
// unreadableAfter checks in a row: a deleted or unreadable binary or config
// is tampering too, and the server then sees a change from the last hash
// (agent_integrity_changed). One failure alone stays "" (not a change): a
// file being replaced by an upgrade can fail once.
const (
	Unreadable      = "unreadable"
	unreadableAfter = 2
)

var hashFailures = map[string]int{} // by file kind; currentIntegrity's callers are serial

// hashOrMark hashes path, or reports it Unreadable after repeated failures.
// An unconfigured path ("" with kind config) is never a failure.
func hashOrMark(kind, path string) string {
	if path == "" && kind == "config" {
		return ""
	}
	if h := sha256File(path); h != "" {
		hashFailures[kind] = 0
		return h
	}
	hashFailures[kind]++
	if hashFailures[kind] >= unreadableAfter {
		return Unreadable
	}
	return ""
}

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
	in := Integrity{ConfigSHA256: hashOrMark("config", ConfigPath)}
	if err == nil {
		in.BinarySHA256 = hashOrMark("binary", exe)
	} else {
		in.BinarySHA256 = hashOrMark("binary", "")
	}
	if in == (Integrity{}) {
		return nil
	}
	return &in
}

// SendStopping tells the server this agent is stopping on purpose, so it can
// tell a stopped service (alert) from a host shutting down or a lost network.
func SendStopping(cfg *config.Config, c *client.Client, reason string) {
	if s := updateStatus(); s != nil && s.State == "installing" {
		reason = "agent_update" // the installer is stopping the service
	}
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
	// >0: the server takes this many legacy log lines per POST /api/ingest/logs.
	LogBatchMax int `json:"log_batch_max"`
	// Version of the enabled YARA rule set ("" when there is none); the
	// rules themselves are fetched from /api/ingest/yara-rules on change.
	YaraRulesHash string `json:"yara_rules_hash"`
	// "<seq>:<action>" of the known-malware hash set, "" when it is off (or
	// the server is older); changes are fetched from /api/ingest/malware-hashes.
	MalwareHashesVersion string `json:"malware_hashes_version"`
	// Opaque version of the web blocklist, compared as a string only (the
	// server's format is "<group>:<seq>[+]"); "" when web protection is off
	// (or the server is older). Changes come from /api/ingest/web-blocklist.
	WebBlocklistVersion string `json:"web_blocklist_version"`
	// Version of the group policy (internal/policy); "" from older servers.
	PolicyVersion string `json:"policy_version"`
	// Set while this agent's group rollout wants it on another version.
	Update *update.Offer `json:"update"`
	// AgentToken is a rotated token (only to agents that sent TokenRotation).
	AgentToken string `json:"agent_token,omitempty"`
}

var (
	lastOK           atomic.Int64 // unix nanos of the last 200 heartbeat
	evidenceV2       atomic.Bool
	evidenceBatchMax atomic.Int64
	logBatchMax      atomic.Int64
)

// LastContact is when a heartbeat last got a 200 from the server (zero
// before the first one).
func LastContact() time.Time {
	n := lastOK.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// LogBatchMax is how many legacy log lines the last successful heartbeat said
// one POST /api/ingest/logs takes; 0 (older server) means one per POST /log.
func LogBatchMax() int { return int(logBatchMax.Load()) }

// EvidenceHealth, when set (durable evidence mode), returns the journal's
// cumulative health for the heartbeat. Counters live in the journal, so a
// failed heartbeat loses nothing: the next one reports the same totals.
var EvidenceHealth func() any

// WebBlockHealth, when set, returns the web protection state for the heartbeat.
var WebBlockHealth func() any

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
			TokenRotation: 1}
		if EvidenceHealth != nil {
			payload.EvidenceHealth = EvidenceHealth()
		}
		if WebBlockHealth != nil {
			payload.WebBlockHealth = WebBlockHealth()
		}
		payload.Update = updateStatus()
		resp, err := c.Post("/api/ingest/heartbeat", payload)
		if err != nil {
			slog.Error("heartbeat failed", "err", err)
			time.Sleep(interval)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			lastOK.Store(time.Now().UnixNano())
			var hbResp HeartbeatResponse
			if err := json.Unmarshal(body, &hbResp); err == nil {
				storeUninstallHash(hbResp.UninstallTokenSHA256)
				if hbResp.AgentToken != "" {
					storeAgentToken(c, hbResp.AgentToken)
				}
				storeEvidenceProtocols(hbResp.EvidenceProtocols, hbResp.EvidenceBatchMax)
				logBatchMax.Store(int64(max(hbResp.LogBatchMax, 0)))
				if Updater != nil {
					Updater.Offer(hbResp.Update)
				}
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

// ErrUninstallUnverifiable: the agent is enrolled but its uninstall token
// hash is gone and the server can't be asked for it.
var ErrUninstallUnverifiable = errors.New("uninstall refused: this agent is enrolled but its uninstall token " +
	"hash is missing and the SIEM server can't be reached to check the token; restore connectivity and retry")

// VerifyUninstallToken is what the package removal hooks call. An agent that
// never enrolled has no token to check, so removal is allowed. An enrolled
// one whose hash file is missing (deleted to get around the check) asks the
// server for it, and refuses when the server can't be reached.
func VerifyUninstallToken(configPath, token string) error {
	want, err := os.ReadFile(UninstallHashPath(configPath))
	if errors.Is(err, os.ErrNotExist) {
		cfg, enrolled, cerr := enrollment(configPath)
		if cerr != nil {
			// a config made unreadable must not turn the check off
			slog.Warn("uninstall check: agent config unreadable", "err", cerr)
			return ErrUninstallUnverifiable
		}
		if !enrolled {
			return nil
		}
		hash, ferr := fetchUninstallHash(configPath, cfg)
		if errors.Is(ferr, errAgentUnknown) {
			// deleted on the server (or its token revoked): nothing protects it any more
			slog.Info("uninstall check: the server no longer knows this agent")
			return nil
		}
		if ferr != nil || len(hash) != 64 {
			slog.Warn("uninstall token hash unavailable", "err", ferr)
			return ErrUninstallUnverifiable
		}
		if werr := os.WriteFile(UninstallHashPath(configPath), []byte(hash+"\n"), 0o600); werr != nil {
			slog.Warn("could not store the uninstall token hash", "err", werr)
		}
		want = []byte(hash)
	} else if err != nil {
		return err
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(token)))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(got[:])), []byte(strings.TrimSpace(string(want)))) != 1 {
		return ErrUninstallRefused
	}
	return nil
}

// enrollment reads only what the uninstall check needs from the config (a
// full config.Load also validates settings that don't matter here). No
// config at all: the agent was never set up.
func enrollment(configPath string) (*config.Config, bool, error) {
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, false, err
	}
	return &cfg, cfg.Agent.Token != "" && cfg.Server.URL != "", nil
}

// errAgentUnknown: the server rejects this agent's token (the agent was
// deleted there).
var errAgentUnknown = errors.New("agent unknown to the server")

// fetchUninstallHash asks the server for this agent's uninstall token hash
// with a "stopping" heartbeat (reason uninstall_check): it carries the hash
// and, unlike a normal heartbeat, dispatches no pending task (tests replace
// it).
var fetchUninstallHash = func(configPath string, cfg *config.Config) (string, error) {
	token := cfg.Agent.Token
	if rotated := LoadStoredToken(configPath, TokenBasisOf(cfg.Agent.Token)); rotated != "" {
		token = rotated
	}
	c := client.New(cfg.Server.URL, token)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.PostContext(ctx, "/api/ingest/heartbeat", HeartbeatRequest{
		AgentID: cfg.Agent.ID, Status: "stopping", Version: AgentVersion, Reason: "uninstall_check",
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 401, 403, 404:
		return "", errAgentUnknown
	default:
		return "", errors.New("heartbeat: status " + resp.Status)
	}
	var hb HeartbeatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&hb); err != nil {
		return "", err
	}
	return hb.UninstallTokenSHA256, nil
}
