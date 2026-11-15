---
name: defense-evasion-tampering
description: Someone is blinding the defenders - Windows event log cleared (wevtutil, Security log cleared), SIEM agent service tampering, an agent tampering command, a sensor exclusion tampered, an agent that stopped reporting or lost a sensor, Defender disabled, or shadow copies or backups deleted. Treats evasion as a sign of an intrusion already under way and finds it.
---

# Defense evasion and tampering investigation

Clearing logs or stopping the agent is rarely the attack itself. It hides
an attack that already happened or is about to. Goal: confirm the
tampering, then find what it was meant to hide.

## 1. Confirm the tampering
- Log clearing: `run_artifact Windows.EventLogs.LogCleared` (Security
  1102, System 104) for who cleared which log and when.
- Agent tampering: `search_events` with `log_type: siem_agent` for the host
  (agent_stopped, integrity changed, sensor silent, exclusion changed) and
  the process or account that ran the command (`process_tree`). Note the
  last telemetry time: the blind window starts there.
- Defender: `Windows.EventLogs.DefenderDetections` and the PowerShell
  script blocks for `Set-MpPreference` / exclusions.
- Backups: shadow-copy deletion (`vssadmin delete shadows`, `wbadmin delete
  catalog`, `bcdedit /set recoveryenabled no`) usually comes just before
  ransomware. If present, follow the ransomware-investigation skill now.

## 2. What it hides
- The window **before** the tampering is where the evidence is. Use
  `event_timeline` and `reconstruct_timeline` for the host and the account
  over the preceding hours: logons, new processes, persistence, outbound
  connections.
- Evidence the attacker could not clear: the SIEM already holds the events
  shipped before the clear. Network sensors (Suricata, firewall) and other
  hosts' logs also record this host's activity during the blind window.
- `correlate_entity` on the account that tampered: other hosts where the
  same account did the same.

## 3. Restore visibility
Recommend restarting the agent and verifying it (integrity and sensors
reporting), re-enabling the logs and Defender, and checking whether an
exclusion was added that would hide a path or process.

## Verdict
- **True positive:** an interactive or unexpected account clears logs or
  stops the agent or protection outside maintenance, or any tampering next
  to other suspicious activity.
- **False positive:** a documented maintenance window, a reimage or
  decommission, or an administrator clearing a full log by policy. Confirm
  it with the change record and the account.

## Report must cover
What was tampered with, by which account and process, the blind window
(start and end), what the surrounding evidence shows happened in it, and
the hosts with the same pattern. The recommended actions: treat the host as
compromised (isolate it, then investigate the activity it hides), restore
and verify telemetry, reset the account used, and protect the agent with
the uninstall token and tamper alerts.
