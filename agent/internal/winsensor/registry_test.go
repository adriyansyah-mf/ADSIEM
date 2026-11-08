package winsensor

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func u16(s string) []byte {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func TestRegDetailsLikeSysmon(t *testing.T) {
	cases := []struct {
		typ  uint32
		data []byte
		want string
	}{
		{regSZ, u16(`C:\Users\a\AppData\Roaming\x.exe`), `C:\Users\a\AppData\Roaming\x.exe`},
		{regExpandSZ, u16(`%APPDATA%\x.exe`), `%APPDATA%\x.exe`},
		{regDWORD, []byte{1, 0, 0, 0}, "DWORD (0x00000001)"},
		{regQWORD, []byte{2, 0, 0, 0, 1, 0, 0, 0}, "QWORD (0x00000001-0x00000002)"},
		{regMultiSZ, append(append(u16("autocheck autochk *"), u16("evil")...), 0, 0), "autocheck autochk * evil"},
		{regBinary, []byte{1, 2}, "Binary Data"},
	}
	for _, c := range cases {
		if got := regDetails(c.typ, c.data); got != c.want {
			t.Errorf("type %d: got %q want %q", c.typ, got, c.want)
		}
	}
	if long := regDetails(regSZ, u16(strings.Repeat("a", 3000))); len(long) != maxDetails {
		t.Fatalf("not cut: %d", len(long))
	}
}

func TestRegDiff(t *testing.T) {
	run := `HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\`
	svc := `HKLM\SYSTEM\CurrentControlSet\Services\`
	old := newSnapshot()
	old.values[run+"OneDrive"] = `C:\Program Files\OneDrive.exe`
	old.values[run+"Gone"] = `C:\old.exe`
	old.keys[svc+"Spooler"] = true
	cur := newSnapshot()
	cur.values[run+"OneDrive"] = `C:\Program Files\OneDrive.exe`
	cur.values[run+"Updater"] = `powershell -w hidden -enc SQBFAFgA`
	cur.keys[svc+"Spooler"] = true
	cur.keys[svc+"EvilSvc"] = true
	cur.values[svc+`EvilSvc\ImagePath`] = `C:\Users\Public\svc.exe`

	got := strings.Join(regDiff(old, cur), "\n")
	for _, want := range []string{
		`EventID=12 Channel="ETW" Provider="SIEMAgent-Registry" EventType="CreateKey" TargetObject="` + svc + `EvilSvc"`,
		`EventID=13 Channel="ETW" Provider="SIEMAgent-Registry" EventType="SetValue" TargetObject="` + svc + `EvilSvc\ImagePath" Details="C:\Users\Public\svc.exe"`,
		`EventType="SetValue" TargetObject="` + run + `Updater" Details="powershell -w hidden -enc SQBFAFgA"`,
		`EventID=12 Channel="ETW" Provider="SIEMAgent-Registry" EventType="DeleteValue" TargetObject="` + run + `Gone"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing:\n%s\nin:\n%s", want, got)
		}
	}
	if strings.Contains(got, "OneDrive") || strings.Contains(got, "Spooler") {
		t.Fatalf("unchanged entries reported:\n%s", got)
	}
	if regDiff(cur, cur) != nil {
		t.Fatal("no change, no lines")
	}
}

func TestRunMRUWatchedWithoutOrderValue(t *testing.T) {
	for _, s := range userSpecs {
		if strings.HasSuffix(s.path, `\Explorer\RunMRU`) {
			if !s.wants("a") || !s.wants("z") || s.wants("MRUList") {
				t.Fatal("RunMRU must report the typed commands (a-z), not MRUList")
			}
			return
		}
	}
	t.Fatal("RunMRU is not watched")
}

func TestRegSpecValueFilter(t *testing.T) {
	s := regSpec{values: []string{"Shell", "Userinit"}}
	if !s.wants("shell") || s.wants("DefaultUserName") || !(regSpec{}).wants("anything") {
		t.Fatal("value filter")
	}
}
