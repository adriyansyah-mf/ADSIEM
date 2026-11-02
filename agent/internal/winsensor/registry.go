package winsensor

import (
	"sort"
	"strings"
)

// LogTypeRegistry carries Sysmon 12/13 lookalikes (Sigma windows/registry_*)
// for the keys malware uses to persist. The agent watches those keys and
// compares their contents, so the writer is unknown (no Image): what was
// written is what the rules look at.
const LogTypeRegistry = "windows_etw_registry"

// GroupRegistry turns the registry watcher off (etw disable list).
const GroupRegistry = "registry"

// regSpec is one persistence location: the values of a key (depth 0), or of
// each of its subkeys (depth 1, optionally in a child key of each).
type regSpec struct {
	path   string   // under the root, e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	depth  int      // 0 or 1
	child  string   // depth 1: read <subkey>\<child> (Services\x\Parameters)
	values []string // only these value names (empty: all)
}

// machineSpecs are watched under HKLM.
var machineSpecs = []regSpec{
	{path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	{path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, values: []string{"Shell", "Userinit", "Taskman", "AppSetup"}},
	{path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, values: []string{"AppInit_DLLs", "LoadAppInit_DLLs"}},
	{path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, depth: 1, values: []string{"Debugger", "GlobalFlag"}},
	{path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`, depth: 1, values: []string{"MonitorProcess", "ReportingMode"}},
	{path: `SOFTWARE\Microsoft\Active Setup\Installed Components`, depth: 1, values: []string{"StubPath"}},
	{path: `SYSTEM\CurrentControlSet\Services`, depth: 1, values: []string{"ImagePath"}},
	{path: `SYSTEM\CurrentControlSet\Services`, depth: 1, child: "Parameters", values: []string{"ServiceDll"}},
	{path: `SYSTEM\CurrentControlSet\Control\Session Manager`, values: []string{"BootExecute"}},
}

// userSpecs are watched under each signed-in user's hive (HKU\<SID>).
var userSpecs = []regSpec{
	{path: `Software\Microsoft\Windows\CurrentVersion\Run`},
	{path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{path: `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, values: []string{"Shell"}},
	{path: `Software\Microsoft\Windows NT\CurrentVersion\Windows`, values: []string{"Load", "Run"}},
	{path: `Environment`, values: []string{"UserInitMprLogonScript"}},
}

// regSnapshot is what a spec saw: value TargetObject -> Details, and the
// depth-1 subkeys (TargetObject of the key).
type regSnapshot struct {
	values map[string]string
	keys   map[string]bool
}

func newSnapshot() regSnapshot {
	return regSnapshot{values: map[string]string{}, keys: map[string]bool{}}
}

func (s regSpec) wants(name string) bool {
	if len(s.values) == 0 {
		return true
	}
	for _, v := range s.values {
		if strings.EqualFold(v, name) {
			return true
		}
	}
	return false
}

// regDiff turns two snapshots of one spec into Sysmon 12/13 lines: new or
// changed values (13 SetValue), removed values (12 DeleteValue), new and
// removed subkeys (12 CreateKey / DeleteKey).
func regDiff(old, cur regSnapshot) []string {
	var out []string
	for _, k := range sortedKeys(cur.keys) {
		if !old.keys[k] {
			out = append(out, line(12, [][2]string{{"Channel", "ETW"}, {"Provider", "SIEMAgent-Registry"},
				{"EventType", "CreateKey"}, {"TargetObject", k}}))
		}
	}
	for _, t := range sortedStrings(cur.values) {
		if prev, ok := old.values[t]; !ok || prev != cur.values[t] {
			out = append(out, line(13, [][2]string{{"Channel", "ETW"}, {"Provider", "SIEMAgent-Registry"},
				{"EventType", "SetValue"}, {"TargetObject", t}, {"Details", cur.values[t]}}))
		}
	}
	for _, t := range sortedStrings(old.values) {
		if _, ok := cur.values[t]; !ok {
			out = append(out, line(12, [][2]string{{"Channel", "ETW"}, {"Provider", "SIEMAgent-Registry"},
				{"EventType", "DeleteValue"}, {"TargetObject", t}}))
		}
	}
	for _, k := range sortedKeys(old.keys) {
		if !cur.keys[k] {
			out = append(out, line(12, [][2]string{{"Channel", "ETW"}, {"Provider", "SIEMAgent-Registry"},
				{"EventType", "DeleteKey"}, {"TargetObject", k}}))
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStrings(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Registry value types (winnt.h).
const (
	regSZ       = 1
	regExpandSZ = 2
	regBinary   = 3
	regDWORD    = 4
	regMultiSZ  = 7
	regQWORD    = 11
)

const maxDetails = 1024

// regDetails formats a value the way Sysmon's Details field does.
func regDetails(typ uint32, data []byte) string {
	var s string
	switch typ {
	case regSZ, regExpandSZ:
		s = utf16le(data)
	case regMultiSZ:
		s = strings.Join(strings.FieldsFunc(utf16leRaw(data), func(r rune) bool { return r == 0 }), " ")
	case regDWORD:
		if len(data) >= 4 {
			v := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
			s = "DWORD (0x" + hex8(v) + ")"
		}
	case regQWORD:
		if len(data) >= 8 {
			lo := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
			hi := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
			s = "QWORD (0x" + hex8(hi) + "-0x" + hex8(lo) + ")"
		}
	default:
		s = "Binary Data"
	}
	if len(s) > maxDetails {
		s = s[:maxDetails]
	}
	return s
}

func hex8(v uint32) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = digits[v&0xf]
		v >>= 4
	}
	return string(b)
}

func utf16leRaw(data []byte) string {
	u := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		u = append(u, rune(uint16(data[i])|uint16(data[i+1])<<8))
	}
	return string(u)
}

func utf16le(data []byte) string {
	return strings.TrimRight(utf16leRaw(data), "\x00")
}
