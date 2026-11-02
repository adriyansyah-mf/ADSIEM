# Windows sensor (ETW)

`agent/internal/winsensor` turns Event Tracing for Windows into Sysmon-like lines, without Sysmon and without a driver. `agent/internal/etw` is the pure-Go consumer: one real-time session per source, events decoded through TDH. Lines use Sysmon's event IDs and field names, so the SigmaHQ windows rules apply; their log types (`windows_etw_*`) keep the source visible. `worker/worker/sigma_logsource.py` maps each log type and EventID to its Sigma category.

| Log type | EventID | Sigma category | Source |
|---|---|---|---|
| `windows_etw_process` | 1 | process_creation | kernel logger (command line, user) joined with Microsoft-Windows-Kernel-Process (full image, integrity level) |
| `windows_etw_network` | 3 | network_connection | Microsoft-Windows-Kernel-Network TCP connect/accept |
| `windows_etw_dns` | 22 | dns_query | Microsoft-Windows-DNS-Client 3008 |
| `windows_etw_file` | 11 | file_event | Microsoft-Windows-Kernel-File 30 (new file) and 27 (rename, as the new name with `SourceFilename`) |
| `windows_etw_file` | 23 | file_delete | Kernel-File 26 |
| `windows_etw_file` | 1100 | none (search only) | per-process summary over the budget |
| `windows_etw_image` | 7 | image_load | Kernel-Process 5 ImageLoad in a process |
| `windows_etw_image` | 6 | driver_load | Kernel-Process 5 ImageLoad into PID 0/4 |

## File events

Measured on the Windows runner (`etw.TestFileAndImageSources`): the event header's PID is the process that acted. CreateNewFile (30) and DeletePath (26) carry the long path. RenamePath (27) carries only the new path; the old one is the Create (12) of the same `FileObject`, kept in a bounded map, whose `FileName` may be in 8.3 form (`RUNNER~1`), so its directory is expanded with `GetLongPathName`. Reads, writes and closes are not subscribed: writes carry no name, and in-place overwrites are left to the anti-ransomware work.

A Create (12) with `FILE_DELETE_ON_CLOSE` in `CreateOptions` is reported as a delete: the file goes when its last handle closes, without a DeletePath event.

`Image` and `User` come from the process-start session. A short-lived child's file or image event often arrives before its start, so a line for a process not seen yet (or seen only with a bare name) waits up to 3 s and is sent as soon as the full image path arrives, or with what is known after that. 1.5 s was measured too short on a busy CI runner.

Not reported: directories (`FILE_DIRECTORY_FILE`), paths without a drive letter (named pipes, mailslots, the network redirector), `\Windows\Prefetch\`, `\System Volume Information\`, `\$Extend\`, and the agent's own process (its journal and spill files would feed back).

Like the Linux sensor, one process ships at most 30 file lines a minute; the rest are counted into one `FileAction="summary"` line (EventID 1100, `Creates`/`Renames`/`Deletes` and a sample path) when its minute ends.

## Image and driver loads

Every DLL load would bury everything else, so a (process image, DLL) pair is reported once a day: after warm-up only loads not seen before arrive (a new tool, or a known process loading something it never did). Driver loads are reported once a day per path. ETW carries no signature or hashes, so `Signed`, `Signature` and `Hashes` are empty: rules that need them do not fire on these lines. Driver classification (PID 0/4) follows the provider's documentation; the runner loaded no driver during the tests, so it is not measured.

## Shipped rules on this telemetry

Written against the Sigma categories, so they also fire on Sysmon's events (`tests/worker/test_windows_rules.py` runs each on both):

| Category | Rule | Level |
|---|---|---|
| file_event | Ransom Note Dropped | high |
| file_event | Executable Or Script Dropped In Startup Folder (`.lnk` left out) | high |
| file_event | Office Application Drops Executable Or Script | high |
| file_event | LSASS Memory Dump File Created | critical |
| file_delete | Windows Event Log File Deleted | high |
| image_load | System Binary Loads DLL From User-Writable Folder (ProgramData and Roaming left out) | medium |
| image_load | .NET Runtime Loaded Into Office Application | medium |
| driver_load | Kernel Driver Loaded From User-Writable Folder | high |
| driver_load | Known Vulnerable Driver Loaded (BYOVD) | high |
| process_creation | Shadow Copies Or Backups Deleted | critical |
| process_creation | Defender Protection Disabled Via PowerShell | high |
| process_creation | Event Log Cleared With Wevtutil | high |

## Configuration

```yaml
etw:
  mode: auto               # auto: off when Sysmon is installed; on; off
  disabled_events: []      # file, image
```

## Testing

- `go test ./internal/winsensor` (any OS): mapping from recorded events, skips, budget and summary, image dedupe, driver loads.
- Native, elevated Windows (the `native-evidence` job of `.github/workflows/windows-agent.yml` runs `tests/windows/evidence-resume.ps1`): `etw.TestFileAndImageSources` logs the provider schemas; `winsensor.TestSensorReportsFilesAndImageLoads` runs the sensor and requires create, rename (with source), delete and a DLL load by `rundll32` as lines.
- `tests/worker/test_windows_etw_file.py`: decoders and Sigma categories.
- Not measured yet: CPU and line volume on a busy desktop. Kernel-File 12 (every open) is subscribed for rename sources and is the expensive part; `disabled_events: [file]` turns it off.
