//go:build linux || windows

package task

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestPluginMemYaraOwnProcess(t *testing.T) {
	marker := "plugin-memyara-marker-7f3a91"
	held := []byte("::" + marker + "::")
	var rows []map[string]any
	err := pluginMemYara(context.Background(), map[string]any{
		"pid":   float64(os.Getpid()),
		"rules": []any{map[string]any{"name": "pack", "content": `rule m { strings: $a = "` + marker + `" condition: $a }`}},
	}, func(r map[string]any) error { rows = append(rows, r); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || rows[0]["Rule"] != "m" || rows[0]["Namespace"] != "pack" || !strings.HasPrefix(rows[0]["Address"].(string), "0x") {
		t.Fatalf("rows = %v", rows)
	}
	_ = held
}

func TestPluginMemYaraReportsBrokenRules(t *testing.T) {
	var rows []map[string]any
	err := pluginMemYara(context.Background(), map[string]any{
		"pid":   float64(os.Getpid()),
		"rules": []any{map[string]any{"name": "bad", "content": "rule {"}},
	}, func(r map[string]any) error { rows = append(rows, r); return nil })
	if err == nil || len(rows) != 1 || rows[0]["Rule"] != "bad" {
		t.Fatalf("err=%v rows=%v", err, rows)
	}
}

func TestRunMemoryScanTask(t *testing.T) {
	marker := "task-memory-scan-marker-c0ffee"
	held := []byte(marker)
	res, err := runMemoryScan(os.Getpid(), []any{map[string]any{"name": "p", "content": `rule t { strings: $a = "` + marker + `" condition: $a }`}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ProcessesScanned != 1 || len(res.Matches) == 0 || res.Matches[0]["rule_name"] != "t" {
		t.Fatalf("result = %+v", res)
	}
	_ = held
}
