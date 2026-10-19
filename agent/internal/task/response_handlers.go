package task

import (
	"fmt"
	"os"
	"path/filepath"
)

func (r *Runner) stateDir() string {
	if r.cfg != nil && r.cfg.Agent.StateDir != "" {
		return r.cfg.Agent.StateDir
	}
	return "/var/lib/siem-agent"
}

func (r *Runner) handleKillProcess(params map[string]any) (any, error) {
	pid, ok := asInt(params["pid"])
	if !ok || pid <= 0 {
		return nil, fmt.Errorf("kill_process: pid is required")
	}
	force, _ := params["force"].(bool)
	grace, _ := params["grace_seconds"].(float64)

	res, err := killProcess(pid, force, grace)
	if err != nil {
		return map[string]any{
			"pid":     pid,
			"refused": res.Refused,
			"error":   err.Error(),
		}, err
	}
	return res, nil
}

func (r *Runner) handleQuarantineFile(params map[string]any) (any, error) {
	path, _ := params["path"].(string)
	if path == "" {
		return nil, fmt.Errorf("quarantine_file: path is required")
	}
	cfgPath := r.configPath()
	if abs, err := filepath.Abs(path); err == nil && cfgPath != "" && abs == cfgPath {
		return nil, fmt.Errorf("quarantine_file: refusing to quarantine the agent's own config")
	}
	return quarantineFile(path)
}

func (r *Runner) handleRestoreFile(params map[string]any) (any, error) {
	path, _ := params["path"].(string)
	if path == "" {
		return nil, fmt.Errorf("restore_file: path is required")
	}
	return restoreFile(path)
}

func (r *Runner) handleAgentIntegrity() (any, error) {
	return CheckIntegrity(r.configPath(), r.stateDir())
}

func (r *Runner) configPath() string {
	if r.cfg != nil && r.cfg.Agent.ConfigPath != "" {
		return r.cfg.Agent.ConfigPath
	}
	return "config.yaml"
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func initQuarantineState(stateDir string) {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return
	}
	setQuarantineStore(filepath.Join(stateDir, "quarantine.json"))
}
