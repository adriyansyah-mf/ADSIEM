# Group policies

Dashboard → **Policies** (`/api/policies`, edit with `agents:manage`, inside your own group unless superadmin). One policy per agent group; Linux and Windows agents read the same one. A group without its own policy follows the `default` group's; without that, the built-in defaults (everything on).

## Settings

| Setting | Effect | Default |
|---|---|---|
| Execution prevention | prevention rules and known-malware blocking; off also empties the BPF LSM rules and stops the fanotify helper (Linux) | on |
| Known-malware hashes | off / detect / block for this group; empty uses the global setting (Malware hashes page) | global |
| YARA on-access | scan new and changed files in the watched folders (files still go to the known-malware check) | on |
| Ransomware | stop (kill the encrypting process), report only, off | stop |
| Isolate on ransomware | cut the host off the network when ransomware is confirmed | off |
| Pop-ups | tell the signed-in Windows user when malware is found or stopped | on |

Agents get `policy_version` with every heartbeat and fetch the policy (`POST /api/ingest/policy`) when it changes: a change applies within a minute, no restart. The agent keeps the last policy in `<state_dir>/policy.json`. A protection turned off in the agent's local `config.yaml` (e.g. `ransomware.disabled`, `prevention.disabled`, `notify.disabled`, `ransomware.report_only`) stays off whatever the policy says.

## Exclusions

Each exclusion has a kind, a value and the protections it applies to:

| Kind | Matches |
|---|---|
| Path or folder (`path_prefix`) | a file or program path starting with the value (`C:\Tools\Sysinternals\`, `/opt/backup/`) |
| Program (`image`) | a full path, or a file name in any folder (`veeam.exe`) |
| SHA-256 | the file's hash |
| Command line contains | a substring of the command line |

| Scope | Where it is honoured |
|---|---|
| Prevention rules | the agent: hash rules, and every rule where fanotify decides (Linux without BPF LSM, Windows). Path / folder / parent rules the BPF LSM enforces in the kernel are explicit: change the rule. |
| Known malware | the agent: exec checks and files written in watched folders |
| YARA on-access | the agent: the file is not YARA-scanned |
| Ransomware | the agent: no heuristics for that program, and no kill (canary hits are still reported) |
| Alerts | the worker: a rule match on an event about an excluded program, file, hash or command line raises no alert (logged as `alert_excluded_by_policy`) |

Windows paths compare without case. Example: the Process Explorer driver flagged as "Kernel Driver Loaded From User-Writable Folder" → path `C:\Users\<user>\AppData\Local\Temp\PROCEXP152.SYS`, scope Alerts.

## Not in this version

Telemetry event groups (`etw.disabled_events`, `linux_sensor.disabled_events`) and opt-in features (firewall, netwatch, local detect) are still set in the agent's config: they need a restart of the sensors.
