# File scans (quick, full, custom)

On-access scanning only sees files as they are written. A file scan reads what is already on the disk: malware that was there before the agent, and files whose hash, rule or model verdict appeared later. Linux and Windows agents do the same.

| Kind | What |
|---|---|
| `quick` | Linux: `/tmp`, `/var/tmp`, `/dev/shm`, `/var/www`, `/srv/www`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, cron (`/etc/cron.*`, `/var/spool/cron`), `/etc/systemd/system`, `/etc/init.d`, `/etc/rc.local`, `/etc/ld.so.preload`, `/root`, and per user `Downloads`, `Desktop`, `.local/bin`, `.config/autostart`, `.config/systemd`, `.ssh`. Windows: `%SystemRoot%\Temp`, per user `Downloads`, `Desktop`, `Documents`, `AppData\Local\Temp`, `AppData\Roaming` (Startup included), the all-users Startup folder, `C:\Users\Public`, `C:\ProgramData`, `C:\inetpub\wwwroot`. |
| `full` | Linux: `/`, without `/proc`, `/sys`, `/dev`, `/run` and pseudo or network file systems (NFS, SMB, sshfs, overlay, squashfs...: read from `/proc/self/mountinfo`). Windows: every fixed drive, without `WinSxS` and `System Volume Information`. |
| `custom` | The paths given (folders or files). |

Every file goes through the on-access engines (`agent/internal/yarascan`): [known-malware hashes and TLSH variants](malware-hashes.md), the [YARA rules](yara.md), the [static ML models](static-ml.md), and the files inside archives, disk images, shortcuts and HTML. Files are checked even when unchanged since an on-access check. Detections arrive as the usual alerts with the scan named: `malware.engine` (known malware), `trigger` (YARA match), `ml.trigger` (static ML) is `quick_scan`, `full_scan` or `custom_scan`. Blocking follows the group policy (known-malware action, `ml_action`).

## Starting a scan

- **On request**: Agents → an agent → **Scan files**, or `POST /api/agents/{id}/file-scan` with `{"kind": "quick" | "full" | "custom", "paths": [...]}` (permission `agents:manage`, the agent's group). It is the agent task `file_scan`; its result is the summary.
- **On a schedule**: group policy (Policies page) `quick_scan_time` (`"HH:MM"`, every day) and `full_scan_schedule` (`"<mon..sun> HH:MM"` or `"daily HH:MM"`), in the endpoint's local time; empty is off. A slot missed while the endpoint was off runs later the same day; a newly installed agent waits for the next slot. A due full scan replaces that day's quick scan. The last runs are kept in `<state_dir>/file_scan_schedule.json`.

One scan runs at a time; a second request fails with "a file scan is already running".

## Load on the endpoint

- The scan's thread runs at low priority: Linux nice 19 and the idle I/O class (`ioprio_set`), Windows background mode (`THREAD_MODE_BACKGROUND_BEGIN`: low CPU, I/O and memory priority).
- It reads at most 40 MB a second, and files larger than `yara.max_file_size_mb` (default 32) are skipped and counted.
- Left out: group policy exclusions with the YARA scope, files the agent quarantined, and the agent's state directory.

## Progress and summary

Log type `file_scan` (`decoders/file_scan.yaml`): a line when it starts, one a minute while it runs, one when it ends:

```
event=file_scan status=completed scan_id=414eaf0699592b1b kind=full files=120394 bytes=9876543210 detections=2 errors=3 skipped=40 duration=3712 requested="task 7c1d…" roots="/"
```

Fields: `scan.status` (started, running, completed, cancelled), `scan.id`, `scan.kind`, `scan.files`, `scan.bytes`, `scan.detections`, `scan.errors` (unreadable files), `scan.skipped` (too large or excluded), `scan.duration` (seconds), `scan.requested` (`schedule` or `task <id>`), `scan.roots`. A scan stops (cancelled) when the agent stops.
