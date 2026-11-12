package notify

import (
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/projscan"
)

// A malicious-looking project pops up once (its summary line), with the
// directory and the worst finding; a clean scan and the per-finding lines
// don't.
func TestProjectScanMessage(t *testing.T) {
	trig := projscan.Trigger{Dir: "/home/ana/test-task", Kind: "git_clone", Origin: "https://github.com/acme/t.git", Image: "git"}
	lines := projscan.Lines(trig, projscan.Result{Files: 4, Findings: []projscan.Finding{
		{Severity: "high", Check: "vscode_autorun", File: ".vscode/tasks.json", Detail: `task "eslint-check" runs when the folder is opened and runs curl`},
		{Severity: "medium", Check: "js_loader", File: "lib/a.js", Detail: "obfuscated code"},
	}})
	msg := Message(projscan.LogType, lines[0])
	for _, want := range []string{"looks malicious", "test-task", ".vscode/tasks.json", "eslint-check", "Do not install or run it"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	for _, l := range lines[1:] {
		if m := Message(projscan.LogType, l); m != "" {
			t.Errorf("finding line popped up: %q", m)
		}
	}
	clean := projscan.Lines(trig, projscan.Result{Files: 4})
	if m := Message(projscan.LogType, clean[0]); m != "" {
		t.Errorf("clean scan popped up: %q", m)
	}
	// medium findings are leads for the analysts, not a "looks malicious" pop-up
	medium := projscan.Lines(trig, projscan.Result{Files: 4, Findings: []projscan.Finding{
		{Severity: "medium", Check: "vscode_autorun", File: ".vscode/tasks.json", Detail: "runs when the folder is opened"},
	}})
	if m := Message(projscan.LogType, medium[0]); m != "" {
		t.Errorf("medium scan popped up: %q", m)
	}
}
