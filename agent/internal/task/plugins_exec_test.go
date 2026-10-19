//go:build !windows

package task

import (
	"context"
	"strings"
	"testing"
)

func runExec(t *testing.T, args map[string]any) ([]map[string]any, error) {
	t.Helper()
	var rows []map[string]any
	err := pluginExec(context.Background(), args, func(r map[string]any) error {
		rows = append(rows, r)
		return nil
	})
	return rows, err
}

func TestExecCapturesOutputAndExitCode(t *testing.T) {
	rows, err := runExec(t, map[string]any{
		"command": "/bin/sh",
		"args":    []any{"-c", "echo one; echo two; echo oops >&2; exit 3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r["Stream"].(string)+":"+r["Text"].(string))
	}
	want := []string{"stdout:one", "stdout:two", "stderr:oops"}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("rows %v, want prefix %v", got, want)
		}
	}
	last := rows[len(rows)-1]
	if last["Stream"] != "exit" || last["ExitCode"] != 3 {
		t.Fatalf("last row %v", last)
	}
}

func TestExecDoesNotUseAShell(t *testing.T) {
	rows, err := runExec(t, map[string]any{"command": "echo", "args": []any{"$HOME; id", "`whoami`"}})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0]["Text"] != "$HOME; id `whoami`" {
		t.Fatalf("argv was re-parsed: %v", rows[0])
	}
}

func TestExecTimeoutAndOutputCap(t *testing.T) {
	rows, err := runExec(t, map[string]any{"command": "sleep", "args": []any{"5"}, "timeout": 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rows[len(rows)-1]["Text"].(string), "killed after the 1s timeout") {
		t.Fatalf("rows %v", rows)
	}

	rows, err = runExec(t, map[string]any{
		"command": "/bin/sh", "args": []any{"-c", "head -c 5000 /dev/zero | tr '\\0' x"}, "max_output": 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(rows[0]["Text"].(string)); n != 1024 {
		t.Fatalf("stdout kept %d bytes, want 1024", n)
	}
	if !strings.Contains(rows[len(rows)-1]["Text"].(string), "output cut at 1024 bytes") {
		t.Fatalf("rows %v", rows[len(rows)-1])
	}
}

func TestExecMissingProgramIsAnError(t *testing.T) {
	if _, err := runExec(t, map[string]any{"command": "definitely-not-a-program-xyz"}); err == nil {
		t.Fatal("want an error")
	}
	if _, err := runExec(t, map[string]any{}); err == nil {
		t.Fatal("want an error for an empty command")
	}
}
