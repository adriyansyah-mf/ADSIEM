package winsensor

import (
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/etw"
)

// Properties as the Windows runner reported them (network_windows_test.go).
func tcp(id uint16, saddr, sport, daddr, dport string) *etw.Event {
	return &etw.Event{Provider: kernelNetworkProvider, ID: id, PID: 6788, Props: []etw.Property{
		{Name: "PID", Value: "6788"}, {Name: "size", Value: "0"},
		{Name: "daddr", Value: daddr}, {Name: "saddr", Value: saddr},
		{Name: "dport", Value: dport}, {Name: "sport", Value: sport},
	}}
}

func knownBeacon(j *processJoiner) {
	j.remember(&process{pid: 6788, image: `C:\Users\alice\beacon.exe`, user: `WIN01\alice`})
}

func TestOutboundConnectionIsInitiatedFromTheLocalSide(t *testing.T) {
	j := joiner()
	knownBeacon(j)
	got := j.network(tcp(tcpConnectV4, "10.1.0.103", "60180", "203.0.113.9", "4444"))
	want := `EventID=3 Channel="ETW" Provider="Microsoft-Windows-Kernel-Network" ProcessId="6788" ` +
		`Image="C:\Users\alice\beacon.exe" User="WIN01\alice" Protocol="tcp" Initiated="true" ` +
		`SourceIp="10.1.0.103" SourcePort="60180" DestinationIp="203.0.113.9" DestinationPort="4444" ` +
		`SourceIsIpv6="false" DestinationIsIpv6="false"`
	if got != want {
		t.Fatalf("line\n got %s\nwant %s", got, want)
	}
}

// An accept has the remote peer as the initiator: Source is remote, as Sysmon.
func TestInboundConnectionHasTheRemotePeerAsSource(t *testing.T) {
	j := joiner()
	knownBeacon(j)
	got := j.network(tcp(tcpAcceptV6, "fe80::1", "3389", "fe80::99", "51000"))
	for _, want := range []string{`Initiated="false"`, `SourceIp="fe80::99"`, `SourcePort="51000"`,
		`DestinationIp="fe80::1"`, `DestinationPort="3389"`, `DestinationIsIpv6="true"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestDNSQueryNamesTheQueryingProcess(t *testing.T) {
	j := joiner()
	knownBeacon(j)
	got := j.dns(&etw.Event{Provider: dnsClientProvider, ID: dnsQueryCompleted, PID: 6788, Props: []etw.Property{
		{Name: "QueryName", Value: "c2.example.com"}, {Name: "QueryType", Value: "1"},
		{Name: "QueryOptions", Value: "720575941453045760"}, {Name: "QueryStatus", Value: "0"},
		{Name: "QueryResults", Value: "203.0.113.9;"},
	}})
	want := `EventID=22 Channel="ETW" Provider="Microsoft-Windows-DNS-Client" ProcessId="6788" ` +
		`Image="C:\Users\alice\beacon.exe" User="WIN01\alice" QueryName="c2.example.com" QueryType="1" ` +
		`QueryStatus="0" QueryResults="203.0.113.9;"`
	if got != want {
		t.Fatalf("line\n got %s\nwant %s", got, want)
	}
}

func TestOtherNetworkAndDNSEventsAreIgnored(t *testing.T) {
	j := joiner()
	if got := j.network(tcp(10, "a", "1", "b", "2")); got != "" { // TCP send: never wanted
		t.Fatalf("send event became %s", got)
	}
	if got := j.dns(&etw.Event{ID: 3006, Props: []etw.Property{{Name: "QueryName", Value: "x"}}}); got != "" {
		t.Fatalf("query start became %s", got)
	}
}

// A process the sensor never saw (started before it) is resolved live.
func TestUnknownOwnerIsResolvedFromTheRunningProcess(t *testing.T) {
	j := newProcessJoiner(func(pid uint32) string {
		if pid == 6788 {
			return `C:\Program Files\App\app.exe`
		}
		return ""
	}, func(p string) string { return p })
	got := j.network(tcp(tcpConnectV4, "10.0.0.1", "1", "10.0.0.2", "443"))
	if !strings.Contains(got, `Image="C:\Program Files\App\app.exe"`) || strings.Contains(got, "User=") {
		t.Fatalf("line %s", got)
	}
}
