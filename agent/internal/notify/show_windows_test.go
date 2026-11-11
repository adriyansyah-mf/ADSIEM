//go:build windows

package notify

import (
	"strings"
	"testing"
)

func TestToastScriptRegistersAUMIDAndKeepsDollarLiteral(t *testing.T) {
	s := buildToastScript("SIEM Agent", "A known malicious file was found:\nC:\\$Recycle.Bin\\it's.exe", `C:\ProgramData\ADSIEM\logo.png`)
	for _, want := range []string{
		`AppUserModelId\`,
		"CreateToastNotifier($aumid)",
		"'" + toastAUMID + "'",
		"$xml = @'\n",
		"\n'@\n",
		`C:\$Recycle.Bin\it&apos;s.exe`,
		"exit 0",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q", want)
		}
	}
	if strings.Contains(s, `CreateToastNotifier("ADSIEM")`) {
		t.Error("script still uses the unregistered AUMID")
	}
}
