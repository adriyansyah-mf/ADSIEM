---
name: phishing-initial-access
description: A document or user action started code - Office or LibreOffice started a shell or script host, Office dropped or ran a program, .NET loaded into Office, ClickFix (a command pasted into the Run dialog), or the IOA chains "Office app started a script host that reached the internet". Confirms phishing, finds the lure and every user and host it reached.
---

# Phishing and initial-access investigation

Goal: confirm the lure ran code, identify the payload and what it fetched,
and find every other recipient who opened it.

## 1. Reconstruct the chain on the first host
- `process_tree` on the alerted host: WINWORD/EXCEL/POWERPNT/soffice →
  cmd/powershell/wscript/mshta/rundll32/regsvr32 → child processes. Note the
  document path (often in `Downloads`, `INetCache\Content.Outlook` or a
  temp folder) and the user.
- ClickFix: the Run-dialog command (`mshta http…`, `powershell -w hidden
  -enc …`) is the payload. Decode base64 arguments in the report.
- `run_artifact Windows.EventLogs.PowerShellScriptBlocks` gives the script
  actually executed (deobfuscated by Windows).
- `run_artifact Windows.Search.FileFinder` on `C:/Users/<user>/Downloads/**`
  and `C:/Users/<user>/AppData/Local/Temp/**` around the alert time, then
  `Windows.Search.FileHash` on what it finds. Check the hashes with
  `known_malware_lookup` / `lookup_malwarebazaar`.

## 2. What it fetched and started
- `run_artifact Windows.Network.Netstat` and `search_events` for the host's
  DNS and connections after the first child process: the download URL and
  the C2. Then follow the c2-beaconing-investigation skill for the
  destination.
- The second stage on disk: `run_artifact Windows.Search.ExecutablesInUserFolders`
  and `Windows.Forensics.Prefetch` show what ran from user folders.
- Persistence it set: `Windows.Sys.Persistence`, `Windows.Sys.Services`,
  and scheduled-task alerts.

## 3. Other recipients
- `search_alerts` and `search_events` for the same document name, hash, URL
  or C2 domain across all hosts. Recipients who only received it have no
  process evidence; list them as **at risk**, not compromised.
- `correlate_entity` on the C2 domain/IP.

## Verdict
- **True positive:** an Office/LibreOffice process starts a script host or
  shell that reaches the internet or drops a program, or a pasted Run-dialog
  command downloads and runs code.
- **False positive:** a signed business add-in or macro that IT deploys
  (same path and hash on many hosts for weeks, no internet download, no
  dropped executable). Confirm with `ueba_top_risky_entities` and history.

## Report must cover
The lure (file name, hash, sender if known), the decoded payload, the
download and C2 addresses, every host that ran it and every user who only
received it, and the persistence found. The recommended actions: isolate
the hosts that ran it, block the URL/domain/IP, add the hashes to Malware
hashes, reset the passwords of the users whose sessions ran it, and purge
the message from every mailbox.
