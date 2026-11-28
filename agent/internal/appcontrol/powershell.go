package appcontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"
)

// PowerShell is the Runner on Windows (nil elsewhere): the script goes in
// -EncodedCommand, so no quoting of paths reaches a command line. Only stdout
// is the result: PowerShell writes progress records to stderr as CLIXML when
// it is not attached to a console, and those must not become the "method".
func PowerShell() Runner {
	if runtime.GOOS != "windows" {
		return nil
	}
	return func(ctx context.Context, script string) (string, error) {
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-EncodedCommand", encode(script))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		out := strings.TrimSpace(stdout.String())
		if err != nil {
			if ctx.Err() != nil {
				// killed: say so, and how far the script got
				return out, fmt.Errorf("powershell: timed out (%v) after %s", ctx.Err(), lastStep(out))
			}
			why := psError(stderr.String())
			if why == "" {
				why = lastLine(cleanStderr(stderr.String()))
			}
			if why == "" {
				why = lastLine(out)
			}
			return out, fmt.Errorf("powershell: %s: %w", why, err)
		}
		return out, nil
	}
}

// lastStep is the last "step: ..." marker a script printed ("the start" when none).
func lastStep(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); strings.HasPrefix(t, "step: ") {
			return strings.TrimPrefix(t, "step: ")
		}
	}
	return "the start"
}

// Supported reports why this Windows cannot build an App Control policy, or
// nil. The scripts need the ConfigCI module and the AllowAll example policy;
// Windows Home ships neither, so every apply failed at Import-Module and was
// retried, each run an encoded SYSTEM PowerShell that raised alerts. Checked
// with os.Stat: no process is started to find out.
func Supported() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return supportedIn(os.Getenv("SystemRoot"))
}

func supportedIn(windir string) error {
	if windir == "" {
		windir = `C:\Windows`
	}
	for _, need := range []string{
		filepath.Join(windir, `System32\WindowsPowerShell\v1.0\Modules\ConfigCI`),
		filepath.Join(windir, `schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml`),
	} {
		if _, err := os.Stat(need); err != nil {
			return fmt.Errorf("App Control needs Windows Pro, Enterprise or Education: %s is missing (Windows Home has no ConfigCI)", need)
		}
	}
	return nil
}

var (
	clixmlError = regexp.MustCompile(`(?s)<S S="Error">(.*?)</S>`)
	clixmlChar  = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)
)

// psError is the first line of the error records in PowerShell's CLIXML
// stderr ("Import-Module : The specified module 'ConfigCI' was not loaded
// ..."), or "" when there are none. cleanStderr drops those records whole.
func psError(s string) string {
	var b strings.Builder
	for _, m := range clixmlError.FindAllStringSubmatch(s, -1) {
		b.WriteString(m[1])
	}
	text := clixmlChar.ReplaceAllStringFunc(b.String(), func(x string) string {
		n, err := strconv.ParseUint(x[2:6], 16, 16)
		if err != nil {
			return x
		}
		return string(rune(n))
	})
	text = html.UnescapeString(text)
	for _, line := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// cleanStderr drops CLIXML progress records, keeping the error text.
func cleanStderr(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#< CLIXML") || strings.HasPrefix(t, "<Objs") {
			continue
		}
		keep = append(keep, t)
	}
	return strings.Join(keep, "\n")
}

// encode is PowerShell's -EncodedCommand form: base64 of UTF-16LE.
func encode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}
