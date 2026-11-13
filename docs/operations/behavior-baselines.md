# Host behaviour baselines

`worker/worker/behavior.py` learns per host, from the telemetry agents already send (Linux eBPF and the `ss` fallback, Windows ETW), what is normal, and reports what is not. Server side only: no agent release needed, Linux and Windows alike.

| Finding | When | Rule (level) |
|---|---|---|
| `behavior_rare_parent_child` | a parent → child pair (by file name) this host never ran, that at most 2 hosts of the group ever ran | Rare Parent-Child Process On Host (medium) |
| `behavior_new_rare_executable` | a program from a user-writable folder (`/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root`, `\Users\`, `\ProgramData\`, `\Windows\Temp\`) first seen on this host and run by no other host of the group | New Rare Executable From User-Writable Folder (medium) |
| `behavior_beaconing` | one program connecting to the same external address and port at least 8 times, median gap 10 s - 1 h, jitter (median absolute deviation / median) at most 0.2; once a day per program, address and port | Periodic Beaconing To External Host (high) |

- **Learning**: first-seen findings start `behavior_learning_hours` (platform setting, default 72) after a host's first process event. Beaconing needs no learning.
- **Fleet prevalence** keeps the noise down: what several hosts of the group do is normal. A beacon destination more than 3 hosts call on a timer (updaters, monitoring) is not reported.
- **Left out of beaconing**: internal/private destinations, inbound Windows connections, DNS/NTP/NetBIOS/mDNS ports.
- **Timing** uses the event's own time when the line carries one (`event.start`, Linux eBPF), so a spilled batch delivered at once still keeps its rhythm; otherwise the time the worker sees the event.
- **State** lives in Redis under `siem:bhv:*` (sets per host and kind, capped at 50,000; fleet sets per group; 30 timestamps per beacon candidate), expiring after 90 days without use.

Findings are pushed back into the log stream as `siem_behavior` lines (`decoders/siem_behavior.yaml`), so dedup, policy exclusions, AI triage and SOAR apply as for any alert. A confirmed beacon destination can be blocked fleet-wide from the IP Blocklist page or a SOAR `ip_block` node.

Tests: `tests/worker/test_behavior.py`.
