# Agent config from the dashboard

An operator can set part of the agents' `config.yaml` per group from the
dashboard (Policies → Agent config). The agent restarts into that overlay and
reports whether it was applied (Agents page).

## What can be set

The overlay holds only a whitelist of fields; the agent drops anything else.
Every field is optional: unset keeps the agent's local value, while an
explicit `false`, `0` or `[]` overrides it. **Overlay fields win over
`config.yaml`.**

| Section | Fields |
|---|---|
| `server` | `url`, `heartbeat_interval` (10-3600) |
| `agent` | `buffer_size` |
| `fim` | `enabled` |
| `firewall` | `enabled`, `backend` (auto, nft, netsh, noop), `dry_run`, `protected_ips`, `isolation_release_after_offline_minutes` |
| `netwatch` | `enabled`, `snapshot_fallback` |
| `etw` | `mode` (auto, on, off), `disabled_events` (file, image) |
| `detect` | `enabled`, `rules`, `max_blocked`, `max_blocks_per_minute` |
| `linux_sensor` | `disabled`, `disabled_events` |
| `ransomware` | `disabled`, `canary_dirs`, `canary_names`, `canary_visible`, `allow_images` |
| `yara` | `watch_paths`, `max_file_size_mb` (1-1024) |
| `memory_sweep` | `disabled`, `interval_minutes` (1-1440) |
| `evidence` | `enabled`, `max_bytes`, `segment_bytes`, `reserved_bytes`, `max_event_bytes` |
| `prevention`, `notify`, `project_scan`, `update` | `disabled` |

Lists hold at most 500 items of 1-1024 characters. The server rejects values
out of range when you save.

**Stays local** (edit `config.yaml` on the host): agent identity and token,
state paths, live response, anti-tamper, update keys, and every other field not
in the table. `logs` and `fim.watch_paths` are not in the overlay either: they
are already managed per agent from the server through the heartbeat.

**`server.url`** may change the port or path only, on the same host, and must
be https. The agent refuses a URL with another host and reports it as an error.

**Groups:** a group with its own policy does not inherit Agent config from
`DEFAULT`. If its Agent config is empty, its agents use their local config.

## Restart behavior

The overlay has its own version (a hash of the overlay). Only a change of that
version restarts agents; other policy changes do not.

- Under the Windows service (SCM) or systemd, the agent shuts down normally
  and exits with code 3, so the service manager starts it again. It waits a
  random 0-60 s first, so a group does not restart in the same second.
- In console mode nothing would start it again: it only logs
  `config changed: restart required`.
- A new `server.url` is probed first, with a POST to `/api/ingest/policy`
  using the agent token. If it fails, the version is rejected and the agent
  does not restart.
- The agent restarts at most once per version. If the running config still
  differs after the restart, it reports `config <version> still differs after
  restart` and stops trying.

## Crash guard and URL fallback

A bad overlay must not take the agent down.

- **Crash guard:** if one overlay version is started 3 times within 10 minutes
  without ever running healthy, it is rejected and the agent boots on its local
  config. An agent counts as healthy after 10 minutes of uptime. Error:
  `config <version> rejected: agent kept failing to start`.
- **URL fallback:** if the overlay's `server.url` has no successful contact for
  10 minutes after boot, the version is rejected and the agent restarts on the
  local URL. Error: `server.url <url> unreachable: no contact for 10m0s`.
- A rejected version is never applied again on that agent (the last 100 are
  kept in `agent_config_state.json` in the state dir). To retry, change the
  overlay: that makes a new version.
- Other errors: `config <version> rejected` (seen again after a rejection),
  `server.url <url> unreachable: <reason>` (probe failed), and
  `server.url: host must stay <host>` (refused field; the rest still applies).

## Reading the status on the Agents page

Each agent shows a badge, compared with the version its group expects:

| Badge | Meaning |
|---|---|
| `diterapkan` | The agent runs the expected config (or the group has none and it runs its local one). |
| `pending` | Waiting for the agent to restart into the expected config. Stays so while the agent is offline or in console mode. |
| `error` | The agent reported a config error; hover for the text. See the errors above. |

No badge means the server does not know what to expect for that agent.

## Data folder ACL

On Windows the ACL of the data directory (it holds `config.yaml` with the
token) is re-applied on every service start, so a restart into a new config
also restores it. This happens only under the SCM: a console run may point at
a config in a user's folder. On Linux, `siem-agent-configure` sets chmod 0600.
