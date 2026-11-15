---
name: windows-persistence-lolbins
description: Windows execution or persistence through built-in tools - base64-encoded or obfuscated PowerShell, suspicious PowerShell script blocks, a new service (especially one pointing to a script or user folder), a new scheduled task, Defender protection disabled via PowerShell, or LOLBins such as mshta, rundll32, regsvr32, certutil, bitsadmin, wmic. Decodes what ran and finds everything it left behind.
---

# Windows persistence and living-off-the-land investigation

Goal: decode what the built-in tools were made to do, find every
persistence item, and decide whether a person or legitimate software is
behind it.

## 1. Decode the execution
- `run_artifact Windows.EventLogs.PowerShellScriptBlocks` gives the script
  Windows actually ran (script block logging decodes `-enc` and most
  obfuscation). Quote the decoded commands in the report.
- `process_tree` for the parent: an Office app, a browser, a service, a
  scheduled task (svchost/taskeng), or WMI (wmiprvse).
- LOLBin patterns:
  - `certutil -urlcache -f` and `bitsadmin /transfer` download files;
  - `mshta http…` and `rundll32 javascript:` run remote script;
  - `regsvr32 /i:http… scrobj.dll` is Squiblydoo;
  - `wmic process call create` launches processes.

## 2. Persistence
- `run_artifact Windows.Sys.Services`: binary paths in user, temp or
  ProgramData folders, `cmd /c` or powershell in the service command,
  random names.
- `run_artifact Windows.EventLogs.ServiceInstalls` gives when they were
  installed and by which account.
- Scheduled tasks: `Windows.EventLogs.Query` with `Channel:
  Microsoft-Windows-TaskScheduler/Operational`, plus the task-creation
  alerts.
- `run_artifact Windows.Sys.Persistence` covers Run keys, startup folders,
  WMI subscriptions and Winlogon/IFEO hijacks.
- Defender tampering: `Windows.EventLogs.DefenderDetections`, plus
  exclusions added (`Add-MpPreference -ExclusionPath`) in the script
  blocks.

## 3. The payload and scope
Hash every file the persistence points to (`Windows.Search.FileHash`), and
check it with `known_malware_lookup` / `lookup_malwarebazaar` and
`Windows.Detection.Yara`. Search the fleet for the same service name, task
name, hash or command line.

## Verdict
- **True positive:** a decoded command downloads or runs remote code,
  disables protection, or installs persistence pointing to an unsigned
  user-folder binary or script.
- **False positive:** IT's management tools (SCCM, Intune, RMM agents)
  running signed scripts from their own folders on many hosts, or vendor
  installers creating their documented services. Check the signer, the
  path and the fleet-wide pattern.

## Report must cover
The decoded commands, every persistence item (name, path, created when and
by whom), the payload hashes, the hosts sharing them, and any protection
disabled. The recommended actions: remove all persistence items at once,
re-enable Defender and remove its exclusions, block the hashes and
download URLs, reset the account that created them, and turn on
PowerShell script block logging fleet-wide if it was off.
