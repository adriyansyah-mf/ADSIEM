package appcontrol

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf16"
)

// PowerShell is the Runner on Windows (nil elsewhere): the script goes in
// -EncodedCommand, so no quoting of paths reaches a command line.
func PowerShell() Runner {
	if runtime.GOOS != "windows" {
		return nil
	}
	return func(ctx context.Context, script string) (string, error) {
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-EncodedCommand", encode(script))
		out, err := cmd.CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil {
			return text, fmt.Errorf("powershell: %s: %w", lastLine(text), err)
		}
		return text, nil
	}
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
