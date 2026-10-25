//go:build windows

package winsensor

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

// The sensor on a real Windows host (elevated): a marked command line comes
// out as one Sysmon-like process creation line with both halves joined.
func TestSensorReportsAProcessWithBothHalves(t *testing.T) {
	buf := buffer.New(10000)
	s, err := Start(buf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	time.Sleep(2 * time.Second)

	marker := fmt.Sprintf("siem-sensor-%d", time.Now().UnixNano())
	if err := exec.Command("cmd.exe", "/c", "echo", marker).Run(); err != nil {
		t.Fatal(err)
	}
	sys, _ := windows.GetSystemDirectory()
	self, _ := os.Executable()

	var got string
	deadline := time.Now().Add(15 * time.Second)
	for got == "" && time.Now().Before(deadline) {
		for {
			entry, ok := buf.Pop()
			if !ok {
				break
			}
			logType, _, line := tailer.Decode(entry)
			if logType == LogTypeProcess && strings.Contains(line, marker) {
				got = line
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got == "" {
		t.Fatal("no process line for the marked command")
	}
	t.Logf("line: %s", got)
	for _, want := range []string{
		`Image="` + filepath.Join(sys, "cmd.exe") + `"`,
		`CommandLine="cmd.exe /c echo ` + marker + `"`,
		`ParentImage="` + self + `"`,
		`User="`, `IntegrityLevel="High"`,
	} {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			t.Errorf("missing %s", want)
		}
	}
}

// A TCP connection and a DNS query from this process come out as Sysmon 3
// and 22 lookalikes naming this test binary.
func TestSensorReportsConnectionsAndQueries(t *testing.T) {
	buf := buffer.New(10000)
	s, err := Start(buf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
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
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	name := fmt.Sprintf("siem-sensor-%d.example.com", time.Now().UnixNano())
	_, _ = net.LookupHost(name)
	self, _ := os.Executable()

	var outbound, inbound, query string
	deadline := time.Now().Add(15 * time.Second)
	for (outbound == "" || inbound == "" || query == "") && time.Now().Before(deadline) {
		for {
			entry, ok := buf.Pop()
			if !ok {
				break
			}
			logType, _, line := tailer.Decode(entry)
			switch {
			case logType == LogTypeNetwork && strings.Contains(line, `DestinationPort="`+port+`"`) && strings.Contains(line, `Initiated="true"`):
				outbound = line
			case logType == LogTypeNetwork && strings.Contains(line, `DestinationPort="`+port+`"`) && strings.Contains(line, `Initiated="false"`):
				inbound = line
			case logType == LogTypeDNS && strings.Contains(line, name):
				query = line
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("outbound: %s", outbound)
	t.Logf("inbound: %s", inbound)
	t.Logf("query: %s", query)
	if outbound == "" || inbound == "" || query == "" {
		t.Fatalf("outbound %v inbound %v query %v", outbound != "", inbound != "", query != "")
	}
	for _, l := range []string{outbound, inbound, query} {
		if !strings.Contains(strings.ToLower(l), strings.ToLower(`Image="`+self+`"`)) {
			t.Errorf("not attributed to this process: %s", l)
		}
	}
	if s.Dropped() != 0 {
		t.Errorf("%d events dropped on an idle runner", s.Dropped())
	}
}
