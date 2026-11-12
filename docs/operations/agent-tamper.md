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
