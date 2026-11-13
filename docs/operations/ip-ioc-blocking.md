# IP IoC blocking on endpoints

Agents drop or report traffic to and from IP indicators of compromise in real time, on Linux and Windows, without packet capture or a driver.

## Where the list comes from

`ip_block_entries` (server-api `app/services/ip_blocks.py`), per group plus `*` for every group:

- **Dashboard → IP Blocklist** (`/api/ip-blocks`): an address or CIDR, a reason, an optional expiry. Analysts may block internal (private) hosts.
- **SOAR → Block IOC → `ip_block`** (`worker/worker/soar/nodes.py`): the alert's group, for `days` (default 30). Automation refuses private and special space.
- Always refused: loopback, link-local, multicast, reserved, unspecified, and networks broader than /16 (IPv4) or /48 (IPv6).

SOAR `web_block` puts a domain on the Web Protection blocklist of the alert's group the same way (the group's allowlist still wins).

## What agents do

The group policy's **IP IoC blocklist** (`ip_ioc`, Policies page) decides:

| Mode | Sync | Firewall | `ioc_match` alerts |
|---|---|---|---|
| `block` (default) | yes | drops traffic both ways | yes, `blocked=true` |
| `detect` | yes | nothing | yes, `blocked=false` |
| `off` | no (list dropped) | nothing | no |

The heartbeat names `ip_blocklist_version` (`<group>:<seq>:<mode>`); `agent/internal/ipblock` syncs deltas from `POST /api/ingest/ip-blocklist`, saves the list in the state dir (`ip_blocklist.json`) and re-applies it at start. Routine changes are spread over a minute across the fleet.

- **Linux**: one atomic `nft -f` transaction rebuilds table `inet siem_ioc` (interval sets `v4`/`v6`, input/output/forward chains at priority -10, no established-connection accept, so existing connections to a newly listed address are cut too).
- **Windows**: Windows Filtering Platform filters from user mode (`fwpuclnt.dll`, no driver, no signing): one block filter per CIDR on `ALE_AUTH_CONNECT` and `ALE_AUTH_RECV_ACCEPT` (v4/v6), in a **dynamic session**: Windows deletes them when the agent's engine handle closes, so nothing outlives the agent. A change builds the new session before closing the old one. ALE filters stop new connections; an established one stays until it closes. If WFP refuses, the list falls back to `SIEM-IOC-in/-out` netsh rules.
- **Both**: the firewall's anti-lockout guard drops any entry covering the SIEM server, the default gateway, loopback or `firewall.protected_ips`; refused entries are logged and reported in the `ioc_set_applied` `firewall_gate` event. At most 50,000 entries are enforced.

## Detection

The agent watches its own network telemetry as it is buffered: `linux_network_connect/accept` (eBPF), `linux_network_snapshot` (the `ss` fallback), `windows_etw_network`. A connection to or from a listed address becomes an `ioc_match` line (deduplicated per address and process for 10 minutes, at most 120 a minute):

- `Connection To IP IoC Blocked` (medium): the firewall dropped it.
- `Connection To IP IoC Not Blocked` (high): `detect` mode, or the firewall could not take the list.

Fields: `threat.indicator.ip`, `threat.indicator.cidr`, `threat.indicator.provider` (manual, soar), `threat.indicator.description`, `process.executable`, `process.pid`, `network.direction`.

## Troubleshooting

- No `ioc_match` but traffic dropped: on Windows a WFP block happens before the connect completes and ETW may not report it; the block is still in force (`firewall_gate` `ioc_set_applied`).
- `firewall backend cannot enforce the IP IoC blocklist` in the agent log: `firewall.enabled` is false or the backend degraded (no `nft`/`CAP_NET_ADMIN`, not elevated). Matches are still reported, as not blocked.

Tests: `tests/server-api/test_ip_blocks.int.py`, `tests/worker/test_ip_iocs.py`, `tests/worker/test_ioc_match.py`, `tests/worker/test_soar_new_nodes.py`, `agent/internal/ipblock`, `agent/internal/firewall/ioc_test.go`, `wfp_types_test.go`, and `wfp_windows_test.go` on the windows-agent runner.
