---
name: data-exfiltration-investigation
description: Data may be leaving - potential data exfiltration via HTTP POST, unusually large outbound transfers, uploads to file-sharing or paste sites, archive tools (7z, rar, tar) packing many files before an outbound transfer, rclone/mega/curl -T, or a UEBA anomaly on bytes out. Decides what left, how much, and to where.
---

# Data exfiltration investigation

Goal: establish whether data left, which data, how much, to where, and who
or what sent it. Records here may become legal or regulatory evidence:
quote times and byte counts exactly.

## 1. The transfer
- `aggregate_events` for the host: bytes out per destination per hour, over
  the alert window and the days before. One destination taking most of the
  upload volume, at night or over a weekend, stands out.
- `search_events` for the destination: domain, URL, method (POST/PUT),
  user agent. File-sharing (mega, transfer services, pastebins, cloud
  buckets), personal email, and bare IPs are the usual targets.
- `pivot_ioc` on the destination; check whether other hosts send there.

## 2. What was sent
- `process_tree` and `Windows.Network.Netstat` / `Linux.Network.Netstat`
  give the process making the transfer (rclone, curl, a browser, a script,
  an implant).
- Staging: archives created just before (`run_artifact
  Linux.Search.FileFinder` / `Windows.Search.FileFinder` for
  `*.zip, *.7z, *.rar, *.tar.gz` in temp and user folders), and the source
  folders the archiver read (`process_tree` command lines,
  `recent_fim_changes`).
- Database dumps: `mysqldump`/`pg_dump` runs or large `SELECT … INTO
  OUTFILE` queries before the transfer.

## 3. Who
The user account and session behind the process: an attacker with stolen
credentials, an implant, or an insider (`ueba_top_risky_entities`, the
account's recent logons and their sources).

## Verdict
- **True positive:** sensitive data or archives sent to a destination that
  no business process uses, or by a process or account that has no reason
  to send it.
- **False positive:** backups, sync clients (OneDrive, Google Drive)
  configured by IT, software update uploads, log shipping. Check that the
  destination and the account are the sanctioned ones.

## Report must cover
The destination, the volume (bytes) and time window, the data (folders,
archive names, databases) or "unknown" when the content cannot be
recovered, the process and account, and whether the transfer continues.
The recommended actions: block the destination, isolate the host if an
implant or attacker is behind it, disable or reset the account, preserve
the evidence, and inform the data owner and legal or the CSIRT as policy
requires.
