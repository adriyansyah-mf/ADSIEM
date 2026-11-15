---
name: cryptominer-investigation
description: High CPU from an unknown process, a binary running from /tmp, /var/tmp or /dev/shm, stratum or mining-pool connections, XMRig/kinsing strings, or a YARA coin-miner match. Confirms a miner, finds how it starts again, and how it got in.
---

# Cryptominer investigation

Goal: confirm the miner, find everything that restarts it, and find the
entry point. A miner is rarely alone: the same access can be sold or reused.

## 1. Identify the process
- `run_artifact Linux.Detection.SuspiciousProcesses` lists processes from
  writable or memory-backed paths and deleted binaries.
- `run_artifact Linux.Sys.Pslist` gives each process's command line, user,
  parent and RSS. Miners hide as `kworkerd`, `[kthreadd]`, `systemd-logind`
  or `.x`, run from `/tmp/.X11-unix` or `/dev/shm`, and pass `-o`/`--url`
  with a pool.
- `run_artifact Linux.Network.Netstat` shows connections to pool ports
  (3333, 4444, 5555, 7777, 14444, 45700) or to the pool's domain.
- `run_artifact Linux.Memory.Yara` with `Pid` set to the suspected PID. Use
  one PID, not 0: scanning every process is heavy on small hosts.

## 2. Find what restarts it
Miners come back after a kill. Check all of these:
- `run_artifact Linux.Sys.Persistence` for cron (including
  `/var/spool/cron/crontabs/*`), systemd units, rc.local, profile scripts,
  and `authorized_keys`.
- Watchdog scripts that curl or wget the miner again (`search_events` for
  curl/wget in `linux_process_exec` on the host).
- Competing-miner killers: scripts that `pkill` other miners are a hallmark
  of kinsing, TeamTNT and outlaw.

## 3. Find the entry point
Common entry points: weak SSH passwords (`search_alerts` for SSH brute force
from the same IPs, then a successful login), exposed Redis/Docker/K8s APIs,
vulnerable web apps (see the webshell-investigation skill), and Confluence,
WebLogic or Log4Shell exploits. Correlate the first miner execution time
with logins and web requests just before it.

## Verdict
- **True positive:** a pool connection, mining command-line flags, or a YARA
  miner match from an unexpected binary or user.
- **False positive:** an approved research or benchmark workload. Confirm
  with the host owner; it then belongs in an exclusion, not silence.

## Report must cover
The binary (path, hash), the pool and wallet if visible, every persistence
item, the entry point, and the account used. The recommended actions: kill
the process and remove every persistence item in one go (otherwise it
returns), quarantine the binary, add its hash to Malware hashes, close the
entry point, and rotate the credentials.
