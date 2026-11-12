# Host isolation

`isolate_host` (the console's Isolate button, a SOAR action, or anti-ransomware with `isolate`) cuts a host off the network in both directions, IPv4 and IPv6. Connections that are already open are cut too. The agent keeps what it needs to stay manageable:

- the SIEM server (every address its name resolves to, and the local subnet it is reached through);
- loopback, IPv6 link-local and multicast (`::1`, `fe80::/10`, `ff02::/16`), and the default gateway;
- the DNS servers in `/etc/resolv.conf` (Linux), so the server's name still resolves;
- DHCP (v4 and v6), so the host keeps its lease;
- `firewall.protected_ips` from the agent config.

## How

| OS | Mechanism |
|---|---|
| Linux | an nft table of its own, `inet siem_isolate`, applied in one transaction: input and output chains at priority -10 with `policy drop`, accepting only the allow sets (`allow4`, `allow6`). It runs before `siem_fw` and has no `established` accept, so an open C2 session dies. |
| Windows | every firewall profile set to `blockinbound,blockoutbound`, plus two allow rules `SIEM-Isolate-Allow-In/Out` for the list above. A block rule would not work here: Windows block rules win over allow rules. |

On Windows the firewall engine isolates when `firewall.enabled` is set. Without it, the agent uses `netsh` directly as before: same rule names, both directions, the server only. Either path releases the other's isolation.

## Safety

The agent must stay reachable, or nothing can release the host. So:

- **No server address, no isolation.** The request fails when the server's name has never been resolved.
- **A firewall that blocks nothing reports an error.** That covers the firewall being disabled or having no backend (no nft, no elevation). It never reports success. Dry-run answers `isolated: false, dry_run: true` and lists `would_allow`.
- **The last good addresses are kept.** If a DNS lookup fails, the server stays in the allow list.
- **The address is re-resolved every minute** while the host is isolated, and the allow list follows a server that moved.
- **Dead-man switch.** If no heartbeat has reached the server for `isolation_release_after_offline_minutes` (default 60), the agent releases the isolation itself and logs `firewall_unisolated` with the reason. The clock starts at the isolation, or at the agent's restart, whichever is later. A negative value turns this off.
- **Restarts keep the isolation.** It is stored in `<state_path>.isolation.json` and re-applied at start. If the server can't be resolved at start, the stored allow list is used. The old block-rule isolation of earlier versions (`reason: isolate_host`) is migrated to the new mechanism.
- A server rule sync (`Sync`) never touches the isolation.

## Config

```yaml
firewall:
  enabled: true
  isolation_release_after_offline_minutes: 60   # 0: 60; negative: never
```

## Events

`firewall_gate` lines with `event=firewall_isolated`, `firewall_unisolated` (with `error=<why>` when the dead-man switch released it) and `firewall_isolation_restored`.

## Tests

- `internal/firewall/isolate_test.go`: the engine against a fake backend. Covers fail-closed, no-op backend, backend failure, release, the dead-man switch (and turning it off), DNS failure and a moved server, restart, legacy migration, and sync.
- `backend_isolate_test.go`: the netsh calls and rollback, and the nft script (one transaction, no `established` accept).
- `nft_isolate_netns_test.go`: the real kernel in a throwaway network namespace (`FIREWALL_NETNS_E2E=1`, no root needed). Packets to the server leave over IPv4 and IPv6. Packets to anyone else are refused, and loopback works. The release removes the table.
