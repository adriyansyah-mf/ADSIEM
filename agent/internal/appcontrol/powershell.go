package appcontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"runtime"
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
			why := lastLine(cleanStderr(stderr.String()))
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
