---
name: ot-ics-attack-investigation
description: Alerts on industrial traffic - Modbus or DNP3 writes, PLC programming (UMAS), PLC stop/restart, listen-only, DNP3 restart/stop/disable-unsolicited/file delete, function-code or unit-ID scans, OT ports reached from the internet, or Suricata ICS/SCADA signatures. Finds the source, the physical effect, and the IT host the attacker came through.
---

# OT / ICS attack investigation

PLCs, RTUs and relays cannot run an agent or live response. Their evidence is
the network record (Suricata Modbus/DNP3 events) and the IT hosts around
them: HMI, SCADA server, historian and engineering workstation. Think about
**physical effect** first: what does this device control, and is the process
safe right now?

## 1. What happened to the process
- `search_events` with `log_type: suricata` and the target device IP. Read
  the `ot.*` fields:
  - `ot.function_code`: Modbus 5/6/15/16/22/23 are writes, 8 is
    diagnostics, 43/14 is device identification, 90 is UMAS programming.
    DNP3 2 is write, 3-6 are select/operate, 13/14 are restarts, 18 stops
    the application, 21 disables unsolicited reporting, 27 deletes a file.
  - `ot.unit_id`, plus `ot.address` and `ot.quantity` for the registers or
    coils written.
- Order the events: recon (identification, scans) → access → manipulation
  (writes, programming, stop) → impair (listen-only, disable unsolicited,
  delete file). How far did it get?
- Raise **process safety** at the top of the report: the setpoints written,
  devices stopped or restarted, and alarms suppressed. Operators must check
  the physical state on site; the SIEM cannot see it.

## 2. Where did it come from
- **A public IP:** the OT device is exposed to the internet. That is the
  finding and the urgent fix.
- **An internal IP:** which host is it? `list_hosts` / `correlate_entity` on
  the IP. If it is the engineering workstation or HMI, investigate that host
  as the IT foothold:
  - `run_artifact Windows.Sys.Pslist` and `Windows.Network.Netstat` for the
    tool sending Modbus/DNP3 (not the vendor's engineering software? Python,
    `modbus-cli`, Metasploit, a renamed binary);
  - `Windows.EventLogs.RDPLogons` and `Windows.EventLogs.FailedLogons` for
    who logged in, and from where;
  - `Windows.Sys.Persistence`, `Windows.Search.ExecutablesInUserFolders`.
  - Then follow the lateral-movement-investigation skill back to the IT
    entry point.
- A host that is **not** a known master for that PLC is the key anomaly.
  Ask whether this pair has ever talked before (`aggregate_events` on
  `source.ip` for the device over the past weeks).

## 3. Legitimate or not
Planned maintenance from the engineering workstation (a program download
or restart during a change window) is normal. Look for a matching change
ticket or notes in the case. Without one, treat programming and stop
commands as hostile until the site confirms otherwise.

## Verdict
- **True positive:** commands from the internet; programming, stop or
  listen-only outside maintenance; writes from a host that never controls
  this device; or scans and identification from a non-engineering host.
- **False positive:** the documented master or HMI doing routine polling and
  setpoint writes, or a vendor engineer's sanctioned session (confirm it).

## Report must cover
The devices affected and what they control (from the case or an analyst
note; say "unknown" if you cannot tell), the command sequence with times
and function codes, the source and the IT foothold, and the physical-safety
checks for operators. The recommended actions: isolate the source host
(IT side), block the source at the OT firewall, have operators verify
setpoints and PLC mode on site, compare the PLC program with the known-good
backup, and remove internet exposure.
