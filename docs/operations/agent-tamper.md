# Agent tamper protection

## Uninstall token

Every agent has an uninstall token, shown on Agents → agent → Uninstall token. The server derives it from `JWT_SECRET` and the agent's ID, and the agent only ever holds its SHA-256, which arrives with every heartbeat and is kept in `uninstall.sha256` next to `config.yaml`. Package removal (deb `prerm`, rpm `%preun`, the MSI) runs `siem-agent -verify-uninstall -token <token>` (or `$SIEM_UNINSTALL_TOKEN`) and stops when the exit code isn't 0:

| Situation | Result |
|---|---|
| right token | removed |
| wrong or missing token | refused (exit 3) |
| agent never enrolled (no `agent.token` in the config, or no config) | removed: there's no token to check |
| enrolled, `uninstall.sha256` missing | the agent asks the server for the hash with a `stopping` heartbeat (`reason=uninstall_check`, no task is dispatched), stores it, then checks the token |
| enrolled, hash missing, server unreachable or too old to answer | refused: "restore connectivity and retry" |
| config unparseable | refused |

Deleting the hash file or breaking the config used to turn the check off. A running agent also rewrites a missing hash file on its next heartbeat.

## Detections

Rule `SIEM Agent Tampering Command` (`rules/siem_agent_tamper_commands.yaml`) matches:

- **Windows**
  - `sc`, `net`, `taskkill`, PowerShell or `reg` against the SIEMAgent service.
  - `logman stop|update|delete` or `Stop-/Remove-EtwTraceSession`, `Set-/Remove-EtwTraceProvider` on a `SIEMAgent-*` ETW session. This blinds the agent while it keeps running (T1562.006).
  - `takeown` or `icacls` on the `SIEMAgent` install folder (T1222).
- **Linux**
  - Package removal.
  - `rm`, `mv`, `cp`, `chattr`, `truncate` or `shred` on the agent's files.
  - `chmod` or `chown` on the binary or the service unit. Not on the config: the installer sets its mode.

Other existing coverage: `SIEM Agent Service Tampering` (start type changed, service key written outside SCM/MSI), `SIEM Agent Network Blocked by WFP` (EDRSilencer-style filters), `SIEM Agent Binary/Config Modified` (integrity hashes in the heartbeat, so a local `config.yaml` edit that turns a protection off is reported), `SIEM Agent Stopped`, `SIEM Agent Stopped Reporting`, and `SIEM Agent Heartbeat Spoofing`.

Tests: `agent/internal/heartbeat/uninstall_test.go`, `tests/worker/test_siem_agent_tamper.py`, and `tests/server-api/test_agent_enrollment.int.py` (the stopping heartbeat carries the hash).

## Sensor health (blinding without stopping the agent)

Each heartbeat carries `sensor_health`: per telemetry sensor (`etw` on Windows; `procexec`, `netwatch`, `linsensor` on Linux) whether it started, how many events it put into the agent's buffer, and how many it lost. Windows adds the ETW sessions' own kernel losses (`EVENT_TRACE_CONTROL_QUERY`: `EventsLost` + `RealTimeBuffersLost`) to the agent's queue drops. The counts are taken on the agent (`agent/internal/sensorstat`), so a slow or backlogged server never makes a sensor look silent.

server-api compares each heartbeat with the previous one (`app/services/sensor_health.py`, state in Redis `siem:agent:sensors:<id>`) and stores the snapshot on the agent (Agents page, Sensors column):

| Event | When | Rule |
|---|---|---|
| `agent_sensor_stopped` | a sensor that ran stops or disappears while heartbeats continue | `SIEM Agent Telemetry Sensor Stopped` (high) |
| `agent_sensor_silent` | a sensor with at least 20 events delivered none for `agent_sensor_silence_minutes` (platform setting, default 60; 0 turns it off); once per silence | `SIEM Agent Telemetry Sensor Silent` (high) |
| `agent_sensor_events_lost` | 100+ events lost between two heartbeats; at most hourly per sensor | `SIEM Agent Telemetry Sensor Losing Events` (medium) |

A counter that goes down is an agent restart: the baseline starts over, nothing is reported. Hosts that are idle for an hour at a time (a quiet appliance) can trip the silence rule: raise the setting rather than disabling the rule. The Linux canary (`sensor_blind`) stays: it proves the eBPF hooks still fire, while silence covers ETW and every sensor without a canary.

Tests: `tests/server-api/test_sensor_health.py`, `tests/server-api/test_sensor_health_heartbeat.int.py`, `agent/internal/sensorstat`, `agent/internal/etw` (`TestKernelLostQueriesALiveSession`, Windows runner).
