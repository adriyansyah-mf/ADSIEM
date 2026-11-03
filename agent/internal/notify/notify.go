// Package notify tells the signed-in user what the agent found or stopped,
// like an antivirus pop-up. The agent runs as a Windows service in session 0,
// which cannot draw on a user's desktop, so the message goes to every active
// session with WTSSendMessage (no answer awaited). Other systems: nothing.
//
// Only detections a user should hear about become messages (Message), the
// same message is not repeated within repeatEvery, and at most perMinute go
// out a minute.
package notify

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	Title       = "SIEM Agent"
	repeatEvery = 5 * time.Minute
	perMinute   = 5
	maxPath     = 120
)

// Notifier sends messages through show, deduplicated and rate-limited.
type Notifier struct {
	show func(title, message string) error
	now  func() time.Time

	mu     sync.Mutex
	recent map[string]time.Time
	window []time.Time
	off    bool // the group policy turned pop-ups off
}

// SetEnabled follows the group policy (notify_user).
func (n *Notifier) SetEnabled(on bool) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.off = !on
	n.mu.Unlock()
}

// New returns the platform's notifier (nil where there is none).
func New() *Notifier {
	if platformShow == nil {
		return nil
	}
	return &Notifier{show: platformShow, now: time.Now, recent: map[string]time.Time{}}
}

// Observe is the buffer hook: every pushed entry's log type and line.
func (n *Notifier) Observe(logType, line string) {
	if n == nil {
		return
	}
	msg := Message(logType, line)
	if msg == "" || !n.allow(msg) {
		return
	}
	go func() {
		if err := n.show(Title, msg); err != nil {
			slog.Debug("notify: not shown", "err", err)
		}
	}()
}

func (n *Notifier) allow(msg string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.off {
		return false
	}
	now := n.now()
	if t, ok := n.recent[msg]; ok && now.Sub(t) < repeatEvery {
		return false
	}
	kept := n.window[:0]
	for _, t := range n.window {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	n.window = kept
	if len(n.window) >= perMinute {
		return false
	}
	n.window = append(n.window, now)
	if len(n.recent) > 1000 {
		n.recent = map[string]time.Time{}
	}
	n.recent[msg] = now
	return true
}

// Message is what the user reads for one agent line, or "" when the line
// is nothing a user needs to hear about.
func Message(logType, line string) string {
	f := Fields(line)
	switch logType {
	case "known_malware":
		if f["match"] == "tlsh" {
			return "" // a variant by similarity: for the analysts, not a pop-up
		}
		what := shorten(f["path"])
		if l := f["label"]; l != "" && l != "unknown" {
			what += " (" + l + ")"
		}
		switch f["action"] {
		case "quarantined":
			return "A known malicious file was found and locked so it cannot run:\n" + what
		case "blocked", "terminated":
			return "A known malicious program was stopped:\n" + what
		case "detected":
			return "A known malicious file was found:\n" + what + "\n\nDo not open it. Your security team has been alerted."
		}
	case "yara_match":
		if s := f["severity"]; s == "critical" || s == "high" {
			return fmt.Sprintf("A suspicious file was found:\n%s\n(rule %s)\n\nDo not open it. Your security team has been alerted.",
				shorten(f["file"]), f["rule"])
		}
	case "ml_detection":
		// suspicious scores stay with the analysts: too many false alarms
		// for a pop-up
		if f["level"] == "malicious" {
			if f["action"] == "quarantined" {
				return "A file that looks malicious was found and locked so it cannot run:\n" + shorten(f["path"])
			}
			return "A file that looks malicious was found:\n" + shorten(f["path"]) +
				"\n\nDo not open it. Your security team has been alerted."
		}
	case "windows_exec_prevention", "linux_exec_prevention":
		switch f["action"] {
		case "terminated", "blocked":
			return fmt.Sprintf("A program was stopped by your organization's security policy:\n%s\n(rule %s)",
				shorten(f["Image"]), f["rule"])
		}
	case "script_scan":
		app := f["app"]
		if i := strings.IndexByte(app, '_'); i > 0 {
			app = app[:i] // PowerShell_C:\...\powershell.exe_10.0... -> PowerShell
		}
		switch {
		case f["action"] == "terminated":
			return fmt.Sprintf("A malicious %s script was stopped:\n%s", app, shorten(f["rules"]))
		case f["severity"] == "critical" || f["severity"] == "high":
			return fmt.Sprintf("A malicious %s script was found:\n%s\n\nYour security team has been alerted.", app,
				shorten(f["rules"]))
		}
	case "ransomware_activity":
		if f["confirmed"] == "true" {
			msg := "Ransomware-like activity (files being encrypted) was detected"
			if f["Killed"] != "" && f["Killed"] != "0" {
				msg += " and the program was stopped"
			}
			if img := f["Image"]; img != "" {
				msg += ":\n" + shorten(img)
			}
			return msg + "\n\nSave your work and contact your security team."
		}
	}
	return ""
}

func shorten(p string) string {
	if len(p) <= maxPath {
		return p
	}
	return "..." + p[len(p)-maxPath+3:]
}

// Fields parses key=value pairs; values may be "quoted" with \" \\ \n escapes.
func Fields(line string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(line) {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		eq := strings.IndexByte(line[i:], '=')
		if eq < 0 {
			break
		}
		key := line[i : i+eq]
		i += eq + 1
		var val strings.Builder
		if i < len(line) && line[i] == '"' {
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) {
					i++
					switch line[i] {
					case 'n':
						val.WriteByte('\n')
					default:
						val.WriteByte(line[i])
					}
				} else {
					val.WriteByte(line[i])
				}
				i++
			}
			i++ // closing quote
		} else {
			for i < len(line) && line[i] != ' ' {
				val.WriteByte(line[i])
				i++
			}
		}
		if !strings.ContainsAny(key, " \"") {
			out[key] = val.String()
		}
	}
	return out
}
