---
name: bruteforce-then-login
description: SSH, RDP or web-login brute force, password spraying or username enumeration, especially when a login from the same source then succeeds. Decides whether an account was compromised and what the attacker did after logging in.
---

# Brute force, then a successful login?

Most brute force fails and is noise. The case only matters if a login from
the same source or campaign **succeeded**. Settle that first.

## 1. Did anything succeed?
- `search_events` on the host for the source IP(s), covering both failed
  and successful logins (`linux_auth`: Accepted/Failed password, publickey;
  Windows Security 4624/4625; web app login logs).
- `correlate_entity` on the source IP: other targets of the same campaign.
- On Windows: `run_artifact Windows.EventLogs.FailedLogons` and
  `Windows.EventLogs.RDPLogons` (logon type 10).
- A success from the brute-forcing IP, or from a new IP for an account under
  attack shortly after, is the compromise signal.

## 2. If an account was taken over
- Everything that session did: `event_timeline` for the user and host from
  the login time. Look for commands, sudo use, new users
  (`run_artifact Linux.Sys.Users` / `Windows.Sys.Users`), `authorized_keys`
  changes, and downloads.
- `run_artifact Linux.Sys.Persistence` / `Windows.Sys.Persistence`.
- `run_artifact Linux.Network.Netstat` for current sessions and outbound
  tunnels.
- Other hosts the account then reached (see the
  lateral-movement-investigation skill).

## 3. If nothing succeeded
Say so plainly. It is exposure, not compromise. Recommend: block or
rate-limit the source, keys-only SSH (PasswordAuthentication no), no direct
root login, fail2ban or a VPN in front, and checking that the targeted
usernames exist. Enumeration of real names means they leaked.

## Verdict
- **True positive (compromise):** a successful login tied to the attack.
- **True positive (attempt only):** sustained brute force with no success.
  Report it as exposure with a lower severity.
- **False positive:** a misconfigured internal service or monitoring probe
  retrying with stale credentials, from a known internal address.

## Report must cover
The source IPs and their reputation, the targeted accounts, success or not
(with the evidence), the post-login activity, and the accounts to reset.
