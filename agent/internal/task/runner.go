package task

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/firewall"
)

type TaskDef struct {
	ID       string         `json:"id"`
	TaskType string         `json:"task_type"`
	Params   map[string]any `json:"params"`
}

type TaskResult struct {
	Status string `json:"status"` // done | failed
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Runner struct {
	cfg      *config.Config
	client   *client.Client
	fw       *firewall.Engine
	inflight sync.Map
	// FileScan runs a file_scan task (internal/fullscan, set by main): kind
	// quick, full or custom, paths for custom; it returns the summary.
	FileScan func(kind string, paths []string, requested string) (any, error)
}

func NewRunner(cfg *config.Config, c *client.Client, fw *firewall.Engine) *Runner {
	initQuarantineState(stateDirFor(cfg))
	return &Runner{cfg: cfg, client: c, fw: fw}
}

// StateDir is the agent's state directory (quarantine records, saved sets).
func StateDir(cfg *config.Config) string { return stateDirFor(cfg) }

// QuarantineFile locks a file as the quarantine_file task does (restorable
// with restore_file); the known-malware check uses it in block mode.
func QuarantineFile(path string) error {
	_, err := quarantineFile(path)
	return err
}

func stateDirFor(cfg *config.Config) string {
	if cfg != nil && cfg.Agent.StateDir != "" {
		return cfg.Agent.StateDir
	}
	return "/var/lib/siem-agent"
}

// Dispatch runs a task in a goroutine, skipping if already in-flight.
func (r *Runner) Dispatch(task TaskDef) {
	if _, loaded := r.inflight.LoadOrStore(task.ID, true); loaded {
		return
	}
	go func() {
		defer r.inflight.Delete(task.ID)
		result, err := r.execute(task)
		tr := TaskResult{Status: "done", Result: result}
		if err != nil {
			tr.Status = "failed"
			tr.Error = err.Error()
			slog.Error("task failed", "id", task.ID, "type", task.TaskType, "err", err)
		} else {
			slog.Info("task done", "id", task.ID, "type", task.TaskType)
		}
		r.submitResult(task.ID, tr)
	}()
}

func (r *Runner) execute(task TaskDef) (any, error) {
	switch task.TaskType {
	case "process_list":
		return collectProcesses()
	case "netstat":
		return collectNetstat()
	case "file_list":
		path, _ := task.Params["path"].(string)
		if path == "" {
			path = os.TempDir()
		}
		maxDepth := 2
		if d, ok := task.Params["max_depth"].(float64); ok {
			maxDepth = int(d)
		}
		return collectFileList(path, maxDepth)
	case "file_get":
		path, _ := task.Params["path"].(string)
		if path == "" {
			return nil, fmt.Errorf("path is required")
		}
		return collectFileGet(path)
	case "persistence_check":
		return collectPersistenceCheck()
	case "users_list":
		return collectUsersList()
	case "dmesg_tail":
		lines := 200
		if l, ok := task.Params["lines"].(float64); ok {
			lines = int(l)
		}
		return collectDmesgTail(lines)
	case "open_files":
		limit := 50
		if l, ok := task.Params["limit"].(float64); ok {
			limit = int(l)
		}
		return collectOpenFiles(limit)
	case "yara_scan":
		path, _ := task.Params["path"].(string)
		if path == "" {
			path = os.TempDir()
		}
		recursive, _ := task.Params["recursive"].(bool)
		rulesRaw, _ := task.Params["rules"].([]any)
		return runYaraScan(path, recursive, rulesRaw)
	case "file_scan":
		if r.FileScan == nil {
			return nil, fmt.Errorf("file scanning is not available on this agent")
		}
		kind, _ := task.Params["kind"].(string)
		var paths []string
		if raw, ok := task.Params["paths"].([]any); ok {
			for _, p := range raw {
				if s, ok := p.(string); ok {
					paths = append(paths, s)
				}
			}
		}
		return r.FileScan(kind, paths, "task "+task.ID)
	case "memory_scan":
		pid, _ := task.Params["pid"].(float64) // 0: every process
		rulesRaw, _ := task.Params["rules"].([]any)
		return runMemoryScan(int(pid), rulesRaw)

	case "isolate_host":
		return r.handleIsolateHost()
	case "unisolate_host":
		return r.handleUnisolateHost()
	case "block_ip":
		return r.handleBlockIP(task.Params)
	case "unblock_ip":
		return r.handleUnblockIP(task.Params)
	case "firewall_list":
		return r.handleFirewallList()
	case "firewall_flush":
		return r.handleFirewallFlush()

	case "kill_process":
		return r.handleKillProcess(task.Params)
	case "quarantine_file":
		return r.handleQuarantineFile(task.Params)
	case "restore_file":
		return r.handleRestoreFile(task.Params)
	case "agent_integrity":
		return r.handleAgentIntegrity()

	default:
		return nil, fmt.Errorf("unknown task type: %s", task.TaskType)
	}
}

func (r *Runner) submitResult(taskID string, tr TaskResult) {
	body, _ := json.Marshal(tr)
	url := fmt.Sprintf("/api/tasks/%s/result", taskID)
	resp, err := r.client.PostRaw(url, bytes.NewReader(body))
	if err != nil {
		slog.Error("task result submit failed", "id", taskID, "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Warn("task result rejected", "id", taskID, "status", resp.StatusCode)
	}
}
