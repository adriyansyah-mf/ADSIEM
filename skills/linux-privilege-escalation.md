---
name: linux-privilege-escalation
description: A Linux user or service gained or tried to gain root - unexpected privilege change to root, sudo privilege escalation, sudo denied or failed, sudoers or PAM configuration written or tampered, a user added to a privileged group, SUID abuse, or a kernel exploit. Decides whether root was reached and by whom.
---

# Linux privilege escalation investigation

Goal: decide whether an account or service reached root, how, and what it
did as root. A web user (www-data) or a service account turning into root
is critical.

## 1. Who started and what changed
- `search_events` with `log_type: linux_auth` for the host: sudo commands,
  sudo denials, su, and `pam_unix` sessions around the alert, with the
  invoking user and the TTY. A service account (www-data, postgres,
  tomcat) using sudo or su is abnormal on its own.
- `process_tree` on the root process: its parent chain back to the
  unprivileged process. Look for a jump from uid ≥ 1000 or a service uid
  to 0 without sudo (an exploit or SUID abuse).
- Configuration changes: `recent_fim_changes` and `run_artifact
  Generic.Collectors.File` on `/etc/sudoers`, `/etc/sudoers.d/*`,
  `/etc/pam.d/*` and `/etc/group`. A `NOPASSWD: ALL` line or a pam_permit
  insertion is a backdoor.

## 2. The technique
- **Sudo misconfiguration:** `sudo -l` output in the logs; GTFOBins-style
  abuse (`sudo vim/find/awk/python` spawning a shell).
- **SUID:** `run_artifact Linux.Search.FileFinder` for the suspected
  binary, then `Linux.Search.FileHash`; new SUID files in `/tmp` or a home
  folder are attacker-made.
- **Kernel exploit:** compiler or exploit binaries in `/tmp`/`/dev/shm`
  (`Linux.Detection.SuspiciousProcesses`), and `run_artifact Linux.Sys.Dmesg`
  for oops or segfault lines at that time. Check the kernel version against
  known local root CVEs.
- **Writable cron/systemd run as root:** `Linux.Sys.Persistence`.

## 3. What root did
`event_timeline` for the host after the change: new users
(`Linux.Sys.Users`), SSH keys added, persistence installed, credential
reads (`/etc/shadow`), the agent tampered with, and outbound connections.

## Verdict
- **True positive:** root reached by an account or service with no
  administrative role, through an exploit, misconfiguration abuse or
  backdoored sudoers/PAM.
- **False positive:** an administrator's planned sudo work, configuration
  management (Ansible/Puppet) writing sudoers, or package upgrades
  touching PAM. Confirm the account, the source and a change record.

## Report must cover
The account and the path to root (technique and evidence), the changes made
as root, the persistence and backdoors found, and whether credentials were
read. The recommended actions: isolate the host, remove the backdoors
(sudoers lines, PAM changes, SSH keys, users), patch the kernel or fix the
misconfiguration, and rotate the credentials that root could read.
