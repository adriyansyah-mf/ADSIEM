---
name: c2-beaconing-investigation
description: A host talks to an external system on a schedule or through a suspicious channel - periodic beaconing to an external host, a possible C2 beacon blocked by the firewall, DNS queries for suspicious TLDs, an outbound connection to a dangerous service, a non-service process listening on a port, or a threat-intel C2 match. Finds the implant behind the traffic and whether the channel is live.
---

# C2 and beaconing investigation

Goal: tie the network pattern to a process on the host, decide whether it
is an implant, and find what else it has done.

## 1. The traffic
- `search_events` and `aggregate_events` for the host and destination:
  interval, bytes up versus down, ports, protocol, first and last seen.
  Implants beacon at a fixed interval with jitter, small and regular
  requests, and long sleep gaps.
- `pivot_ioc` / `known_malware_lookup` on the destination IP and domain,
  plus threat-intel enrichment in the alert. Newly registered domains,
  dynamic DNS, odd TLDs and bare IPs on 443 without SNI are signals.
- DNS tunnelling: long, random-looking subdomains of one domain at a
  steady rate.

## 2. The process behind it
- `run_artifact Linux.Network.Netstat` / `Windows.Network.Netstat` while
  the beacon is active gives the PID and image for the connection.
- `process_tree` on that PID: its path, parent, user and start time. A
  binary in a temp or user folder, a renamed system name in the wrong path,
  or a script host / rundll32 / regsvr32 holding the connection is
  suspicious.
- `run_artifact Linux.Memory.Yara` / `Windows.Memory.Yara` with that `Pid`
  (one process, not 0), and `Linux.Memory.RWX` / `Windows.Memory.RWX` for
  injected code.
- How it survives reboots: `Linux.Sys.Persistence` / `Windows.Sys.Persistence`.

## 3. Scope
- The same destination, hash or JA3/SNI from other hosts (`search_events`
  across the fleet, `correlate_entity`).
- What the implant did: child processes, files written, logons from the
  host after the beacon started.

## Verdict
- **True positive:** a regular beacon from an unexpected process or path to
  an unknown or malicious destination, or any confirmed implant.
- **False positive:** software updaters, telemetry agents, monitoring
  checks, NTP or license servers. These are signed, run from program
  folders, and reach their vendor's documented domains. Check that the
  destination belongs to the vendor before closing.

## Report must cover
The destination (IP, domain, reputation), the beacon pattern, the process
and how it persists, the other hosts using the same channel, and whether
the channel was blocked or is still live. The recommended actions: block
the destination at the firewall/web protection, isolate the infected
hosts, kill the process and remove persistence together, add the hash to
Malware hashes, then hunt for the initial access.
