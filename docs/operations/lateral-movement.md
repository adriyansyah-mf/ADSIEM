# Lateral movement graph

`worker/worker/lateral.py` builds, per group, a graph of which host reaches which, how and as whom, from telemetry the platform already has (Linux and Windows alike, server side only).

## Edges

| Source | Becomes | Protocol |
|---|---|---|
| SSH `Accepted …` (`linux_auth`, `event.action: login_success`) | source address → this host | `ssh` |
| Windows 4624 logon type 3 / 10 (`windows_security`) | source address → this host | `logon` / `rdp` |
| Agent outbound connection to an internal address on port 22 / 445 / 3389 / 5985-5986 / 135 | this host → destination | `ssh` / `smb` / `rdp` / `winrm` / `rpc` |

Local logons (types 2, 5, …), loopback and `-` sources, external destinations and other ports are left out. Addresses become hostnames through what each agent reports as its own local address on outbound connections (Redis `siem:lat:ip:<group>:<ip>`, 7 days); unknown ones stay addresses. Edges are stored in `lateral_edges` (group, src, dst, protocol, up to 20 users, count, first/last seen); each edge is written at most once per 5 minutes.

## Findings (after the group's `behavior_learning_hours`, default 72)

| Finding | When | Rule (level) |
|---|---|---|
| `behavior_lateral_new_path` | a path (src, dst, protocol) never seen in the group | New Lateral Movement Path (medium) |
| `behavior_lateral_fanout` | one source opens 5+ new paths within an hour; at most every 6 h | Host Fanning Out To Many New Hosts (high) |
| `behavior_lateral_chain` | a host reached by a new path opens its own new path within 2 h (`A -> B -> C`) | Lateral Movement Chain Across Hosts (high) |

Findings are `siem_behavior` lines, so they reach triage, SOAR and entity risk (tactic `lateral_movement`) like any alert.

## Dashboard

**Lateral movement**: hosts on a circle (agents vs bare addresses, sized by activity), paths coloured by protocol, paths first seen in the window dashed red; click a host to focus on its paths. Window 1 h – 30 days, all or new paths only, table with users and counts. API: `GET /api/lateral/graph?hours=&new_only=&host=` (group scoped, at most 1000 paths).

Tests: `tests/worker/test_lateral_graph.py`, `tests/worker/test_lateral.int.py`, `tests/server-api/test_lateral_api.int.py`.
