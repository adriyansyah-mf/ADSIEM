---
name: credential-access-investigation
description: Something read credentials - LSASS memory read or dumped by an untrusted program, an LSASS dump file created, /etc/shadow accessed, a browser or wallet credential store read by an unexpected program, or credential process memory read on Linux. Decides whether secrets were stolen and which accounts must be reset.
---

# Credential access investigation

Goal: decide whether credentials were actually taken, by what, and which
accounts and hosts are now at risk. A credential theft turns one
compromised host into many, so treat it as urgent.

## 1. The reader
- `process_tree` for the process that read LSASS / shadow / the credential
  store: its image path, signer, command line, user and parent. Common
  tools: mimikatz, procdump `-ma lsass`, `comsvcs.dll MiniDump`,
  `rundll32` with a dump export, nanodump, pypykatz, LaZagne, browser
  stealers in `%APPDATA%`.
- An LSASS dump file: `run_artifact Windows.Search.FileFinder` for `*.dmp`
  in temp and user folders around the alert. A dump that still exists may
  have been copied off the host: check outbound transfers next.
- Linux: who read `/etc/shadow` (root shells only should), and which
  process read the memory of `sshd`, `gnome-keyring`, `sudo` or
  `ssh-agent` (ptrace).

## 2. How the reader got there
Follow the parent chain back (`process_tree`, `event_timeline` for the user
and host): phishing, webshell, RDP login or lateral movement. Use the
matching skill for that stage.

## 3. What the stolen credentials open
- The accounts logged on to the host at the time (`run_artifact
  Windows.Sys.Users`, `Windows.EventLogs.Query` with `Channel: Security`,
  `EventIDs: 4624` for the hours before). Domain admin or service accounts
  on that host are the biggest risk.
- Use after the theft: `search_events` for logons by those accounts from
  new hosts, and `correlate_entity` on each account. See the
  lateral-movement-investigation skill.
- Browser or wallet theft means web, VPN, email and cloud accounts, and
  crypto wallets, are exposed too. Look for an exfiltration connection
  right after the read.

## Verdict
- **True positive:** an unsigned or user-folder program, a LOLBin
  (rundll32/comsvcs, procdump) or an interpreter reads LSASS or dumps it;
  an unexpected program reads a credential store; a non-root process reads
  shadow.
- **False positive:** EDR/AV, backup or password-manager software with a
  known signer reading as designed, or the vendor's own crash dump.
  Confirm the signer and that the behaviour recurs fleet-wide.

## Report must cover
The tool (path, hash, signer), whether a dump or copy left the host, the
accounts exposed (privileged ones first), any use of them after the theft,
and the entry point. The recommended actions: isolate the host, reset every
exposed account (twice for krbtgt if a domain controller was involved),
revoke sessions and tokens, block the tool's hash, and enable LSA
protection / Credential Guard.
