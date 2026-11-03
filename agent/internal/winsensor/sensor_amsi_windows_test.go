//go:build windows

package winsensor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
)

// On a real Windows host (elevated): PowerShell runs a marked command; AMSI
// scans it and the sensor hands the content (deobfuscated text) to OnScript.
func TestSensorReportsAMSIContent(t *testing.T) {
	var mu sync.Mutex
	var got []AMSIScript
	s, err := StartWith(buffer.New(100000), Options{OnScript: func(a AMSIScript) {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	time.Sleep(3 * time.Second)

	marker := fmt.Sprintf("siemamsi%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// concatenated at run time: the deobfuscated text AMSI sees has the whole marker
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command",
		fmt.Sprintf("$m = 'siemamsi' + '%s'; Write-Output $m", strings.TrimPrefix(marker, "siemamsi")))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, a := range got {
			if strings.Contains(string(a.Content), strings.TrimPrefix(marker, "siemamsi")) {
				mu.Unlock()
				t.Logf("AMSI content from pid %d (%s, app %q): %q", a.PID, a.Image, a.App, a.Content)
				if !strings.HasPrefix(strings.ToLower(a.App), "powershell") {
					t.Errorf("app name %q", a.App)
				}
				return
			}
		}
		mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("no AMSI content with the marker; %d scans seen", len(got))
}
