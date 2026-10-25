//go:build windows

package etw

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	kernelNetworkProvider = "{7DD42A49-5329-4832-8DFD-43D979153A88}" // Microsoft-Windows-Kernel-Network
	dnsClientProvider     = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" // Microsoft-Windows-DNS-Client
)

// TestNetworkAndDNSSources connects to a local listener and resolves a unique
// name, then logs every property the network and DNS providers gave for them,
// to decide the field mapping from evidence.
func TestNetworkAndDNSSources(t *testing.T) {
	netRec, dnsRec := &recorder{}, &recorder{}
	ns, err := Start(Config{Name: "SIEMAgent-Test-Network", Providers: []Provider{{GUID: kernelNetworkProvider, Keywords: 0x10 | 0x20}}}, netRec.add)
	if err != nil {
		t.Fatalf("network session: %v", err)
	}
	defer ns.Close()
	ds, err := Start(Config{Name: "SIEMAgent-Test-DNS", Providers: []Provider{{GUID: dnsClientProvider}}}, dnsRec.add)
	if err != nil {
		t.Fatalf("dns session: %v", err)
	}
	defer ds.Close()
	time.Sleep(2 * time.Second)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	name := fmt.Sprintf("siem-etw-%d.example.com", time.Now().UnixNano())
	_, _ = net.LookupHost(name) // NXDOMAIN is fine: the query is what is traced
	pid := uint32(os.Getpid())

	deadline := time.Now().Add(15 * time.Second)
	var conn, query *Event
	for time.Now().Before(deadline) && (conn == nil || query == nil) {
		time.Sleep(500 * time.Millisecond)
		conn = netRec.find(func(e *Event) bool {
			for _, p := range e.Props {
				if (p.Name == "dport" || p.Name == "sport") && p.Value == fmt.Sprint(port) {
					return true
				}
			}
			return false
		})
		query = dnsRec.find(func(e *Event) bool {
			v, _ := e.Get("QueryName")
			return strings.EqualFold(v, name)
		})
	}
	t.Logf("network session: %d events, %d decode errors; dns session: %d events, %d decode errors (test pid %d)",
		len(netRec.events), ns.DecodeErrors(), len(dnsRec.events), ds.DecodeErrors(), pid)
	if conn != nil {
		dump(t, "kernel-network", conn)
	} else if len(netRec.events) > 0 {
		dump(t, "kernel-network sample", netRec.events[0])
	}
	if query != nil {
		dump(t, "dns-client", query)
		for _, e := range dnsRec.events { // every event about the name: query, completion
			if v, _ := e.Get("QueryName"); strings.EqualFold(v, name) && e != query {
				dump(t, fmt.Sprintf("dns-client id %d", e.ID), e)
			}
		}
	} else if len(dnsRec.events) > 0 {
		dump(t, "dns-client sample", dnsRec.events[0])
	}
	if conn == nil || query == nil {
		t.Fatalf("connection seen %v, query seen %v", conn != nil, query != nil)
	}
}
