// agent/internal/task/plugins_exec.go
package task

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// exec runs one program for a command an operator approved on the server
// (server-api/app/services/investigator.py run_command). It is never part of
// an artifact: the server only sends it for an approved command request.
// No shell: command is the program and args its argv, so nothing is
// re-parsed here. Set live_response.disable_commands to refuse it.

const (
	execDefaultTimeout = 60
	execMaxTimeout     = 300
	execDefaultOutput  = 256 << 10
	execMaxOutput      = 1 << 20
)

// capBuffer keeps the first max bytes written and notes that more came.
type capBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
			c.truncated = true
		} else {
			c.buf = append(c.buf, p...)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil // keep draining so the child never blocks on a full pipe
}

func clampInt(v, lo, hi int) int {
	return max(lo, min(v, hi))
}

func pluginExec(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	command := strings.TrimSpace(argString(args, "command", ""))
	if command == "" {
		return errors.New("exec: command is required")
	}
	argv := argStrings(args, "args")
	timeout := clampInt(argInt(args, "timeout", execDefaultTimeout), 1, execMaxTimeout)
	limit := clampInt(argInt(args, "max_output", execDefaultOutput), 1024, execMaxOutput)

	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, command, argv...)
	stdout, stderr := &capBuffer{max: limit}, &capBuffer{max: limit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second // a grandchild holding the pipes can't hang the flow

	started := time.Now()
	err := cmd.Run()
	elapsed := time.Since(started).Milliseconds()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) && cctx.Err() == nil {
		return fmt.Errorf("exec %s: %w", command, err) // never started (not found, not executable)
	}

	for _, s := range []struct {
		name string
		out  *capBuffer
	}{{"stdout", stdout}, {"stderr", stderr}} {
		text := strings.ToValidUTF8(string(s.out.buf), "�")
		text = strings.TrimRight(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		if text == "" {
			continue
		}
		for i, line := range strings.Split(text, "\n") {
			if err := emit(map[string]any{"Stream": s.name, "Line": i + 1, "Text": line}); err != nil {
				return err
			}
		}
	}

	exitCode := -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	summary := fmt.Sprintf("exit code %d after %d ms", exitCode, elapsed)
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		summary = fmt.Sprintf("killed after the %ds timeout", timeout)
	}
	if stdout.truncated || stderr.truncated {
		summary += fmt.Sprintf("; output cut at %d bytes per stream", limit)
	}
	return emit(map[string]any{"Stream": "exit", "Line": 0, "Text": summary, "ExitCode": exitCode})
}

// WithoutCommands is the registry minus exec, for live_response.disable_commands.
func WithoutCommands(plugins map[string]Plugin) map[string]Plugin {
	out := make(map[string]Plugin, len(plugins))
	for name, p := range plugins {
		out[name] = p
	}
	out["exec"] = unsupported("commands are disabled on this agent (live_response.disable_commands in its config)")
	return out
}
