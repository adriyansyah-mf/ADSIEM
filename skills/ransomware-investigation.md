---
name: ransomware-investigation
description: RansomGuard canary or mass-encryption alerts, many files renamed to one new extension, ransom notes, shadow-copy deletion (vssadmin/wbadmin/bcdedit), or a ransomware YARA or hash match. Finds patient zero, the encryptor, the spread and whether data left first.
---

# Ransomware investigation

Goal: stop the spread first, then find the encryptor, patient zero, how it
spread, and whether data was stolen first (double extortion).

## 1. Contain before you dig
Check whether the host is already isolated (the RansomGuard policy may have
done it). If not, put isolation first in the recommendations, together with
every other host showing the same encryptor or extension. Collect while the
host still answers live response.

## 2. The encryptor
- `run_artifact Windows.Detection.SuspiciousProcesses` or the Linux
  equivalent, plus `Windows.Sys.Pslist`: the process with very high file
  write activity, often from `%TEMP%`, `C:\ProgramData` or a user folder.
- `run_artifact Windows.Search.ExecutablesInUserFolders`, then
  `Windows.Search.FileHash` on what it finds; check the hashes with
  `known_malware_lookup` and `lookup_malwarebazaar`.
- `run_artifact Windows.Detection.Yara` on the folder of the suspect
  binary.
- `run_artifact Windows.EventLogs.Query` for shadow-copy and backup tampering
  in the System and Application channels, and
  `Windows.EventLogs.PowerShellScriptBlocks` for staged scripts.

## 3. Patient zero and spread
- `event_timeline` and `reconstruct_timeline` across the hosts with the alert
  give the earliest encryption activity.
- Remote execution before it: `Windows.EventLogs.RDPLogons`,
  `Windows.EventLogs.ServiceInstalls` (PsExec-style services),
  `Windows.EventLogs.FailedLogons`, and `search_events` for SMB/WMI/WinRM
  lateral movement (see the lateral-movement-investigation skill).
- `Windows.EventLogs.LogCleared` shows whether the attacker covered tracks.

## 4. Exfiltration before encryption
Large outbound transfers in the hours to days before encryption point to
double extortion: rclone, mega, `curl -T`, archive tools (7z/rar) on many
files, and new connections to file-sharing services (`aggregate_events` on
destination and bytes).

## Verdict
- **True positive:** mass renames to one extension, ransom notes, or backup
  deletion.
- **False positive:** a backup or encryption tool doing its scheduled job
  (BitLocker, Veeam, an archive job). Confirm with the schedule and the
  signer.

## Report must cover
The encryptor (path, hash, family if known), patient zero and the first
timestamp, every affected host, the spread method, the exfiltration
evidence (or its absence, stated as a gap), and the state of backups. The
recommended actions: isolate the affected hosts, block the hash fleet-wide
(Malware hashes in block mode), reset the credentials used for spread, and
restore from offline backups only after the entry point is closed.
