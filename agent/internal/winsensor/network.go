package winsensor

import (
	"strconv"
	"strings"

	"github.com/siem-platform/agent/internal/etw"
)

// Log types for network connections and DNS queries (Sigma windows /
// network_connection and dns_query).
const (
	LogTypeNetwork = "windows_etw_network"
	LogTypeDNS     = "windows_etw_dns"
)

const (
	kernelNetworkProvider = "{7DD42A49-5329-4832-8DFD-43D979153A88}" // Microsoft-Windows-Kernel-Network
	dnsClientProvider     = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" // Microsoft-Windows-DNS-Client
)

// Kernel-Network TCP events. Measured on the Windows runner: saddr/sport are
// the local side and daddr/dport the remote one, for connect and accept alike.
const (
	tcpConnectV4 = 12
	tcpAcceptV4  = 15
	tcpConnectV6 = 28
	tcpAcceptV6  = 31
)

// networkEventIDs and dnsEventIDs are the only events the kernel delivers
// (per-packet send/receive never reach the agent).
var (
	networkEventIDs = []uint16{tcpConnectV4, tcpAcceptV4, tcpConnectV6, tcpAcceptV6}
	dnsEventIDs     = []uint16{dnsQueryCompleted}
)

// DNS-Client 3008: a query completed, logged in the querying process.
const dnsQueryCompleted = 3008

// network turns a TCP connect or accept into a Sysmon 3 lookalike, Source
// being the side that initiated the connection, as Sysmon reports it.
func (j *processJoiner) network(ev *etw.Event) string {
	var initiated, ipv6 bool
	switch ev.ID {
	case tcpConnectV4:
		initiated = true
	case tcpConnectV6:
		initiated, ipv6 = true, true
	case tcpAcceptV4:
	case tcpAcceptV6:
		ipv6 = true
	default:
		return ""
	}
	pid, ok := number(ev, "PID")
	if !ok {
		pid = ev.PID
	}
	local, _ := ev.Get("saddr")
	localPort, _ := ev.Get("sport")
	remote, _ := ev.Get("daddr")
	remotePort, _ := ev.Get("dport")
	src, srcPort, dst, dstPort := local, localPort, remote, remotePort
	if !initiated {
		src, srcPort, dst, dstPort = remote, remotePort, local, localPort
	}
	image, user := j.owner(pid)
	return line(3, [][2]string{
		{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-Network"},
		{"ProcessId", strconv.FormatUint(uint64(pid), 10)}, {"Image", image}, {"User", user},
		{"Protocol", "tcp"}, {"Initiated", strconv.FormatBool(initiated)},
		{"SourceIp", src}, {"SourcePort", srcPort}, {"DestinationIp", dst}, {"DestinationPort", dstPort},
		{"SourceIsIpv6", strconv.FormatBool(ipv6)}, {"DestinationIsIpv6", strconv.FormatBool(ipv6)},
	})
}

// dns turns a completed query into a Sysmon 22 lookalike.
func (j *processJoiner) dns(ev *etw.Event) string {
	if ev.ID != dnsQueryCompleted {
		return ""
	}
	name, _ := ev.Get("QueryName")
	if name == "" {
		return ""
	}
	qtype, _ := ev.Get("QueryType")
	status, _ := ev.Get("QueryStatus")
	results, _ := ev.Get("QueryResults")
	image, user := j.owner(ev.PID)
	return line(22, [][2]string{
		{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-DNS-Client"},
		{"ProcessId", strconv.FormatUint(uint64(ev.PID), 10)}, {"Image", image}, {"User", user},
		{"QueryName", name}, {"QueryType", qtype}, {"QueryStatus", status}, {"QueryResults", results},
	})
}

// owner is the image and user of pid from the processes seen, resolving a
// bare image name through the running process.
func (j *processJoiner) owner(pid uint32) (image, user string) {
	if p := j.known[pid]; p != nil {
		if !strings.ContainsRune(p.image, '\\') {
			if full := j.fullImage(pid); full != "" {
				p.image = full
			}
		}
		return p.image, p.user
	}
	return j.fullImage(pid), ""
}
