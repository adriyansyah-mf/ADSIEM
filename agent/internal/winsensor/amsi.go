package winsensor

import (
	"encoding/hex"
	"strings"
	"unicode/utf16"

	"github.com/siem-platform/agent/internal/etw"
)

const (
	// Microsoft-Antimalware-Scan-Interface: event 1101 is one AmsiScanBuffer
	// call with what was scanned (PowerShell script blocks and commands,
	// VBScript, JScript, Office VBA, .NET assemblies), after deobfuscation.
	amsiProvider  = "{2A576B87-09A7-520E-C21A-4942F0271D67}"
	amsiScanEvent = 1101
	// GroupAMSI turns the AMSI script source off (etw disable list).
	GroupAMSI = "amsi"
)

// AMSIScript is one AMSI scan's content.
type AMSIScript struct {
	PID     uint32
	Image   string
	App     string // e.g. PowerShell_C:\Windows\...\powershell.exe_10.0..., VBScript, JScript, OFFICE_VBA
	Name    string // content name (a script path, when there is one)
	Content []byte // UTF-8
}

// amsiScript decodes event 1101. TDH formats the binary content as hex
// ("0x..."); PowerShell, VBScript and JScript hand AMSI UTF-16.
func (j *processJoiner) amsiScript(ev *etw.Event) (AMSIScript, bool) {
	if ev.ID != amsiScanEvent {
		return AMSIScript{}, false
	}
	raw, _ := ev.Get("content")
	data, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X"))
	if err != nil || len(data) == 0 {
		return AMSIScript{}, false
	}
	app, _ := ev.Get("appname")
	name, _ := ev.Get("contentname")
	image, _ := j.owner(ev.PID)
	return AMSIScript{PID: ev.PID, Image: image, App: app, Name: name, Content: decodeAMSIContent(data)}, true
}

// decodeAMSIContent returns UTF-8: UTF-16LE text when it looks like it (every
// other byte zero for ASCII), else the bytes as they are (a .NET assembly).
func decodeAMSIContent(b []byte) []byte {
	if len(b) < 2 || len(b)%2 != 0 {
		return b
	}
	zeros, n := 0, len(b)/2
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			zeros++
		}
	}
	if zeros*10 < n*6 { // under 60% ASCII as UTF-16: not text
		return b
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return []byte(string(utf16.Decode(u)))
}
