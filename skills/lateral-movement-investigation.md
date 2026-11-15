---
name: lateral-movement-investigation
description: One host or account reaching others in a new way - remote logins (SSH, RDP, SMB, WinRM, PsExec), new remote-admin connections, a credential used from an unusual host, or a lateral-movement graph alert. Maps the path, the credentials used and every host touched.
---

# Lateral movement investigation

Goal: draw the path host by host, name the credential used at each hop, and
find every host the attacker reached, including the ones that did not alert.

## 1. Map the hops
- `correlate_entity` and `pivot_ioc` on the source host, the account and any
  attacker IP give the hosts and accounts connected to them.
- `search_events` for remote logins **from** the first compromised host:
  SSH (`linux_auth` Accepted), RDP (4624 type 10), network logons (4624
  type 3), service installs (7045), and WinRM/WMI process creation.
- `run_artifact Windows.EventLogs.ServiceInstalls` and
  `Windows.EventLogs.RDPLogons` on each candidate destination.
- `run_artifact Linux.Network.Netstat` / `Windows.Network.Netstat` on each
  hop for live sessions.

## 2. The credentials
For each hop: which account, password or key, and where it came from. Look
for credential access on the previous host (lsass access, SAM dump,
`~/.ssh/id_*` read, `history` files, config files with passwords). A
service account used interactively is a strong signal.

## 3. Every host reached
Run the same checks on each newly found host: persistence
(`Linux.Sys.Persistence` / `Windows.Sys.Persistence`), suspicious
processes, and new users. Note the hosts that are offline or have no agent
as **gaps**, not as clean.

## Verdict
- **True positive:** a hop that no admin workflow explains (wrong source,
  time, account or tool), or one that followed a confirmed compromise.
- **False positive:** a jump host, configuration management (Ansible, SCCM)
  or backup agents connecting as they always do. Check with
  `ueba_top_risky_entities` and the host baselines whether the pair is new.

## Report must cover
The path as an ordered list (host → host, account, method, time), the
credentials to reset, every host reached (and the unreachable ones as
gaps), and the containment order: isolate from the furthest hop back to
patient zero, then reset the credentials.
