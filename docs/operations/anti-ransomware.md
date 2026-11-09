# Anti-ransomware

Roadmap item 3.4. `agent/internal/ransomguard` stops ransomware two ways and reports every detection as a `ransomware_activity` line.

## Canary files

The agent plants `.siem-canary.pdf` and `.siem-canary.docx` in:

- Linux: `/root`, `/home/*`, `/srv`
- Windows: `C:\Users\*\Documents`, `C:\Users\*\Desktop`, `C:\Users\Public\Documents`

Each real directory gets its canaries once. Directories a glob reaches through a junction or symlink are skipped, and so are the `All Users` and `Default User` profile names. On Windows a junction is any reparse point whose tag is a name surrogate; OneDrive Files On-Demand folders are not junctions. What remains is deduped by file identity: volume serial plus file index on Windows, device plus inode on Linux. Before this, `C:\Users\*` reached `All Users\Documents` (→ `ProgramData\Documents` → `Public\Documents`), so two canaries were one file. Each plant overwrote the other, and the periodic check reported `canary_changed` for both every 30 seconds until they retired, with nothing running. A path you list literally in `canary_dirs` is followed even if it is a link, and is still deduped.

They are hidden so users don't see, open or delete them: dot files on Linux (`ls` and file managers skip them; ransomware that walks a directory does not), plus the *hidden* attribute on Windows (not *system*, which some ransomware skips). Agents before this change planted a visible `!siem-canary.pdf`; the agent deletes it on start, but only if the file still holds canary content. `canary_visible: true` restores the visible names.

Web roots (`/var/www`) are not in the defaults any more: deploys (`rsync --delete`, a `git` checkout) rewrite them, which killed the deploy and raised a critical alert each time, and the web server served the canary. The bulk-encryption heuristics below still cover them. Add them back with `canary_dirs` if nothing deploys there.

Nothing legitimate touches them. On Linux the eBPF sensor (`internal/linsensor`) reports a write, rename or delete of a canary with the process that did it, and the guard acts at once (`detection=canary`). On Windows the ETW sensor (`internal/winsensor`, Kernel-File) does the same for renames, deletes and in-place writes (see *Windows writes* below). Every 30 seconds the agent also checks the canaries' content and recreates missing ones. A change found that way has no process attached (`detection=canary_changed`). The periodic check is the only canary signal on hosts without either sensor.

A **write** event on a canary is a hit only once the canary is no longer the canary. The agent records every process that writes a canary: its writers of the last 2 minutes, never just the first. It reads the canary back every 250 ms for one second (on Linux the event is the open, before the data). A read blocked by a lock is tried again, never taken for "unchanged". It then decides:

- **Destroyed** (encrypted, wiped with zeros or a pattern, or the canary text gone), at any read: a hit. Every untrusted writer of the last 2 minutes is stopped and reported. A trusted sync client among them is reported with `response=trusted` and never killed. If no untrusted writer is known, it is a confirmed detection without a process.
- **Other canary text** at the last read (the marker, low entropy): this is OneDrive's Known Folder Move syncing another device's canary. If every recent writer is a trusted sync client, the new content is adopted silently. Otherwise it is left to the periodic check, which reports `canary_changed`, unconfirmed.
- **Unchanged or still unreadable** after a second: handed to the periodic check with its writers kept. If that check finds the canary destroyed within 2 minutes of a write, those writers are stopped as above. So a process that opens a canary, waits, then encrypts it is still stopped by name, not only isolated.

A canary that is being followed this way is skipped by the periodic check, so it is not reported twice.

Renames and deletes of a canary are hits at once, as before, with one exception for sync. When `OneDrive.exe`, `OneDrive.Sync.Service.exe` or `FileCoAuth.exe` renames or deletes a canary **and runs from an install location**, it is not a hit. The admin-only install locations, `<system drive>\Program Files\Microsoft OneDrive\` and `Program Files (x86)\Microsoft OneDrive\`, are trusted as they are. The per-user install, `Users\<user>\AppData\Local\Microsoft\OneDrive\`, can be written by the user, so a binary there is trusted only if it carries a valid Authenticode signature (WinVerifyTrust) whose signer certificate is *Microsoft Corporation*. The verdict is cached per path, size and modification time. In that case the agent reports `detection=canary_sync confirmed=false response=none`, which no rule alerts on, and plants the canary again. This does not count toward retirement. Nothing is trusted by its name: a binary called `OneDrive.exe` anywhere else, or unsigned in the per-user folder, is killed like any other. The same trust rule applies to adopting canary text from a sync client and to skipping the bulk-encryption heuristics for OneDrive.

When a canary changed, the agent reads its new content. The canary itself is hex text after a fixed marker, about 4 bits per byte. The change is **destruction**, and so ransomware or a wiper, when the content:

- looks encrypted: the first 4 KB at 7.2 bits per byte or more, or, with the canary text gone, a first kilobyte that is, and no known file header;
- or no longer starts with the canary text: zeros, a repeated byte, anything else.

Then:

- with a process (a file event): its writers are stopped as above;
- without one (the periodic check, no recent writer): `detection=canary_changed confirmed=true`, so the critical rule fires, and the host is isolated through the firewall engine when `isolate` (or the policy's `ransomware_isolate`) is set: `response=isolated`, `Isolated=true`. Otherwise `response=none`.

A canary rewritten **with canary text** (a clear rewrite), or removed, 3 times within 24 hours (by either path) is **retired**: the agent stops planting it in that spot for 24 hours and reports `detection=canary_retired` once, with the process if one is known. That is a legitimate tool rewriting the directory, not ransomware, which is stopped on the first hit. Destruction never counts toward retirement, in the event path or the periodic check, so repeated attacks, wipers or test runs cannot switch protection off. Retirement lives in memory and resets when the agent restarts.

## Bulk-encryption heuristics (Linux and Windows)

Per process, over a one-minute window of file events:

| Detection | Fires when |
|---|---|
| `extension_change` | 20 or more renames to a new extension, at least 70% of them to the same one (`.locked`, `.enc`, a random suffix) |
| `mass_modify` | 200 or more files written across 10 or more directories, with 50 or more deletes or renames |
| `inplace_modify` | 50 or more files that existed before written across 3 or more directories, no rename needed (each file encrypted over itself) |

For `inplace_modify`, files the process created in the window don't count. On Linux the flags alone can't tell a new file from a rewritten one, so the sensor checks the file's birth time (`statx` btime). An `O_CREAT` open without `O_EXCL` of a file born more than 2 seconds earlier rewrote an existing file. That covers `fopen("wb")` and Python `open(p, "wb")`, which is how script ransomware encrypts in place. The guard gets such an open as a `write`, as Windows reports it; the SIEM line keeps `action=create`. A file the open created, an `O_EXCL` open, or a filesystem without birth times stays a create, so unpacking an archive is not "in place". Only user-data locations count:

- Windows: profiles under `<system drive>\Users\` (not `AppData`), any other drive letter (data disks), and SMB shares. The kernel reports share files as `\Device\Mup\server\share\...`; mapped drives add redirector components, as in `\Device\Mup\;LanmanRedirector\;Z:...\server\share\...`. The sensor gives both to the guard as `\\server\share\...`; pipes and mailslots are left out. Share files reach the guard only: SIEM lines are for drive paths, as before. Data on the system drive outside `Users` (`C:\Data`, `C:\Shares`) is out of scope for `inplace_modify`. Canaries and the other heuristics still cover it.
- Linux: `/home`, `/root`, `/srv`, `/var/www`, `/mnt`, `/media`, `/data` and `/opt/data`. Not `/usr`, `/opt`, `/var/lib`, `/var/cache`, `/tmp` or `/etc`.

Inside those, temp, caches, browser profiles, `Program Files`, `$Recycle.Bin` and the like are skipped too.

An in-place hit is **confirmed** differently: high entropy without a header is not enough, because game assets, packed data and compressed blobs are rewritten in place legitimately. It needs at least half of the samples to have lost the header their extension promises: a `.docx` no longer starting with `PK`, a `.pdf` with no `%PDF`, a `.jpg` with no `FFD8FF`, and so on, now high entropy with no known header. Alternatively, if the process also renamed 5 or more files, at least 70% of them to one new extension, the hit is confirmed like the other heuristics. A `.pak`/`.bin`/`.dat`/`.txt` rewritten with random bytes has no header to lose, so it stays unconfirmed.

The samples are the 3 newest in-place files whose extension promises a header. A Documents tree full of `.txt` and `.csv` does not hide the encrypted `.docx` files. Only when there are none does the agent read the newest files of any kind; those cannot confirm and only give the entropy for the report. An unconfirmed in-place hit does not mute the process for the rest of its minute. The process is evaluated again at every further 50 in-place files, up to 4 times a minute. An earlier `extension_change` or `mass_modify` hit, which still fires once a minute, does not stop the in-place check either. A legitimate program rewriting many files can therefore log up to 4 unconfirmed `inplace_modify` lines a minute.

An `extension_change` or `mass_modify` hit is **confirmed** only if most of the newest files the process wrote (up to 3, first 4 KB each) look encrypted: an entropy of at least 7.2 bits per byte **and** no known file header. Office documents (`PK\x03\x04`, OLE `\xD0\xCF\x11\xE0`), PDF, JPEG, PNG, GIF, RTF, zip/7z/rar/gz/bz2/xz/zstd/cab, MP4/MOV (`ftyp`), MKV, RIFF, Ogg, FLAC, MP3, TIFF, PSD, PE, ELF and SQLite files are high entropy on their own but start with their magic; encryption replaces it. So a photo editor saving 60 JPEGs or Office saving documents stays unconfirmed, while the same files encrypted in place confirm. A file without a known header (txt, csv, ...) confirms on entropy alone. If the first look does not confirm, the files are sampled once more 300 ms later (the newest may still be being written). Unconfirmed hits are logged (`confirmed=false`) but raise no alert and kill nothing. Package managers, git, rsync, backup tools, container engines and build tools are excluded. Add your own with `allow_images`. Interpreters such as python and node are deliberately not excluded.

## Response

On a canary hit or a confirmed heuristic, the agent stops the process and its descendants and reports `response=killed` with `Killed=<n>`. On Linux: SIGSTOP the tree, then SIGKILL. On Windows: `TerminateProcess` on the process, then its descendants (from a process snapshot). It never kills PID 1, itself, systemd, init or sshd (`response=kill_refused`); on Windows it also refuses System, the agent's ancestors (the service host) and critical processes running from System32 (csrss, lsass, services, svchost, wininit, winlogon, smss, ...), reported as `response=kill_failed` with the reason. With `isolate: true` it also isolates the host through the firewall engine, which needs `firewall.enabled`.

A confirmed detection without a process (an encrypted canary found by the periodic check) has nothing to kill: the host is isolated when `isolate` is set (`response=isolated`), otherwise `response=none`.

### Windows writes

Kernel-File write events (event 16, keyword `WRITE` 0x200) carry no file name, only the `FileObject` of the open they write through. When the guard is running, the sensor starts a session of its own for them, `SIEMAgent-FileWrite`, with opens (event 12) and writes. The SIEM's `SIEMAgent-File` session is unchanged. Writes are decoded without TDH: only the header PID and the `FileObject`, read at its fixed offset after `ByteOffset` and `Irp`. That fast decode has three safeguards:

- It is used only for the event versions with that layout (0 and 1); other versions are decoded with TDH.
- At session start the first 64 writes are decoded both ways and compared. On any mismatch the session switches to TDH for good.
- The result is reported as `FastMismatches` and `FastDecodeOff`.

The session's opens and writes have their own bounded queues (8,192 each) with their own drop counters. The run loop serves waiting SIEM events, then opens, before any write, so a write flood can drop only writes: never a SIEM event, and never the opens that name the writes. Each write is resolved through a `FileObject -> name` map that this session's opens fill. The map holds two generations of up to 16,384 objects each: when the current one is full it becomes the previous one, so objects opened just before stay known. A write through an unknown object is counted.

`windows_etw_status` reports all of this when anything changed:

- `Dropped`/`DroppedTotal` (SIEM events);
- `WritesDropped`/`WritesDroppedTotal`, `OpensDropped`;
- `WritesUnresolved` (writes through an unknown object);
- `FastMismatches`, `FastDecodeOff`.

Silence there means the write path works. A climbing `WritesUnresolved` means it doesn't. Writes go to the guard only, as `action=write` events, never as SIEM lines: what is shipped to the server is unchanged. A file written in many chunks is one event per process and file a minute (a bounded set of 16,384). Writes by System (PID 4: the lazy writer and paging I/O) and by the agent itself are dropped.

**Limitation: memory-mapped writes.** A process that encrypts through a memory-mapped view (`CreateFileMapping`/`MapViewOfFile`) issues no write of its own. The data reaches disk as paging writes from System, so its writes are not attributed to it and `inplace_modify` does not see them. Such an encryptor is still caught by a canary it renames or deletes, by the periodic canary check (an encrypted canary is confirmed and isolates the host when `isolate` is set), and by the rename and delete heuristics.

So on Windows the heuristics see creates, writes, renames and deletes: they catch rename-to-new-extension, write-a-copy-then-delete and in-place ransomware, and a canary overwritten in place is a canary hit with its process. Windows installers, servicing, Defender, robocopy, the search indexer and build tools are allowlisted by name (case-insensitively). OneDrive is not on that list: it is trusted only as described for canaries (path, plus signature for the per-user install). Its updater `OneDriveSetup.exe`, which writes hundreds of PNG tiles, is not trusted at all, because malware commonly takes that name; the PNG header check keeps its work unconfirmed. The Windows feed needs the ETW sensor's file group: with `etw.mode: auto` and Sysmon installed, or `etw.disabled_events: [file]`, Windows is back to canary checks without a process to stop.

Measured with the real sensor: a test encryptor was stopped after 20 of 400 files. On a busy desktop, 90 seconds of normal activity (2,107 file events) gave no detections, and a full `go build -a` gave one unconfirmed detection before build tools were allowlisted.

## Precursors (Linux and Windows)

Before it encrypts, ransomware deletes shadow copies and backups, turns boot recovery off, loads a vulnerable signed driver (BYOVD) and stops security products. In the IronChain field case (2026-11-08) all of it ran in about 6 seconds through `cmd /c`, `sc` and `net`. The guard sees every process start: on Windows the ETW sensor's starts with their command line (`OnCommandLine`, fired from the kernel-logger half, the only one that carries it), on Linux the eBPF exec events. It matches the command line case-insensitively, command by command (`cmd /c "a & b"` is two commands; `^` escapes are dropped; PowerShell `-EncodedCommand` is decoded). The wrapping `cmd /c ...` matches as early as the command itself.

**Critical (one is enough):**

| Precursor | Windows | Linux |
|---|---|---|
| `shadow_delete` | `vssadmin delete shadows` (not `/oldest`); `vssadmin resize shadowstorage /maxsize=` under 1 GB; `wmic shadowcopy ... delete`; `Win32_ShadowCopy` with Delete / `Remove-CimInstance` / `Remove-WmiObject` | |
| `backup_delete` | `wbadmin delete catalog`; `wbadmin delete systemstatebackup` or `backup` without `-keepVersions:N` (N ≥ 1), `-deleteOldest` or `-version:` | |
| `boot_tamper` | `bcdedit /set ... recoveryenabled no`, `bootstatuspolicy ignore*`, `safeboot` / `safemode` | |
| `byovd` | `sc create ... type= kernel` (or `filesys`) `binPath= X` or `New-Service -BinaryPathName X.sys`: X outside `System32\drivers` and `System32\DriverStore\FileRepository`; or inside, and the initiator runs from a user-writable place (Users, ProgramData, Windows\Temp, another drive, a share) or the `.sys` was written there in the last 10 min by the initiator or from a user-writable place | |
| `snapshot_delete` | | `lvremove` of an LV whose name contains `snap`; `zfs destroy` of a `@snapshot`; `btrfs subvolume delete` (any abbreviation) of a path containing `snap` |
| `kernel_module` | | `insmod`/`modprobe` of a `.ko` (or `.ko.xz`, `.ko.zst`, `.ko.gz`) under `/tmp`, `/dev/shm`, `/home`, `/var/tmp`, `/run/user` (a relative path is resolved against the process's working directory) |

**Score (`defense_tamper`, 3 distinct indicators from the same initiator within 60 s):** stopping, disabling, deleting or killing a security product's service or process (`net stop`, `sc stop|delete|config start= disabled`, `taskkill /f /im`, `Stop-Service`, `Set-Service -StartupType Disabled`; Defender, Sense, SecurityHealthService, wscsvc and the common third-party products, plus the agent's own `SIEMAgent`); `Add-MpPreference -Exclusion*`; `Set-MpPreference -Disable*` (not `$false`); `netsh advfirewall set ... state off`; `reg add ... DisableAntiSpyware` (or another Defender-off value) with non-zero data. On Linux: `systemctl stop|disable|mask|kill`, `service X stop`, `pkill`/`killall` of `siem-agent`, `auditd` and other security daemons; `auditctl -e 0`; `setenforce 0`. The same indicator seen several times (`cmd /c net stop X` starts cmd, net and net1) counts once.

Everyday admin commands stay quiet: `vssadmin list`, `vssadmin create shadow`, resizing to a percentage or GBs, `bcdedit /enum`, setting recovery back on, `sc query|qc|start`, `net start`, stopping non-security services, `wbadmin get versions|start backup`, `zfs list|snapshot`, `btrfs subvolume list|snapshot`, `modprobe <name>`, `systemctl restart`.

**Response (stop mode).** The guard walks up from the precursor past shells and LOLBins (`cmd`, `conhost`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `wmic`, `sc`, `net`, `net1`; `sh`, `bash`, `dash`, `zsh`, `sudo`, `su`, `env`, `xargs`, `nohup`, ...) to the first other ancestor, the **initiator**, and kills it with its whole tree (the IronChain sample on the Desktop, not `cmd.exe`). A shell is walked past, and a process protected, only by its **full path**: `C:\Windows\System32\cmd.exe` is a shell, `...\Temp\cmd.exe` is an initiator; `services.exe` is protected only from System32. Protected initiators are never killed: System, critical Windows processes, `explorer.exe`, `wmiprvse`, `taskhostw`, `mmc`, `msiexec`, TrustedInstaller, Windows Terminal, sshd; on Linux PID 1, systemd, sshd, login, cron/atd, tmux/screen, terminal emulators, container runtimes, package managers; and the agent with its ancestors. Then only the precursor process is killed and the line says `InitiatorProtected=true`. A process whose image cannot be read counts as protected. A walk that ends at a parent already gone kills the topmost shell. A PID seen starting as one program and now running another (reused) is never killed: the precursor is. The agent's own children (its bcdedit reverts, live-response commands) are ignored.

After a `boot_tamper` hit the change is undone with `bcdedit` (`recoveryenabled yes`, `bootstatuspolicy displayallfailures`, `/deletevalue safeboot`, on the entry the command named), 1 s after the kill; the line says `Reverted=`. The host is isolated when `isolate` (or the policy) asks, as for any confirmed detection.

Every kill is reported, one line each: `detection=precursor confirmed=true response=killed Precursor=<category> CommandLine=... PrecursorImage=... PrecursorPID=... Image=<initiator> PID=<initiator> ... Killed=<n>` (the alert rule's own suppression keeps one incident one alert). In `report_only` the line says `response=none`, nothing is killed or reverted, and repeats from the same initiator are logged once in 10 minutes. With the policy `off` nothing is done or reported (the process-start telemetry still is).

**Exclusions.** The group policy's exclusions with scope `ransomware` apply. They are matched against the precursor process and every process walked up to the initiator, including the shell running a script and the initiator itself.

- `image` exclusions count only with a full path (`C:\Program Files\Veeam\veeam.exe`), never a bare program name (anyone can name a binary `veeam.exe`). `path_prefix` exclusions count too.
- **`command_line` exclusions only cover tools installed in system or program locations.** They are honoured only when the initiator's image is somewhere a standard user cannot write:
  - Windows: under the Windows directory (not `Windows\Temp`, `Tasks`, `Tracing` or the other user-writable folders) or Program Files, as a full long path;
  - Linux: under `/usr`, `/bin`, `/sbin`, `/lib*`, `/opt` or `/etc`, and owned by root.
- Anyone can put the excluded text in a command line, ransomware included. So a program in a user profile, Desktop, Downloads, Temp, `/home`, `/tmp`, `/var/tmp` or `/dev/shm` gets no benefit: it is stopped as usual, and the line says `exclusion_ignored=untrusted_initiator` (and alerts).
- `sha256` does not apply here: no hash is computed for process starts. An excluded precursor is not killed or reverted, and is logged with `response=excluded`, once per initiator in 10 minutes. The *Ransomware Activity On Endpoint* rule ignores `response=excluded`.

**Safe Mode.** At start, when running as the Windows service with the guard on, the agent registers `SIEMAgent` under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal` and `\Network` (default value `Service`), so it also runs if ransomware manages to reboot into Safe Mode. Idempotent.

**Admin tasks.** In stop mode, these everyday admin commands trip a precursor. They are killed and raise the critical alert. Only the command dies, because the console, shell, cron or service behind it is protected. A program run from a user-writable place (Downloads, a portable tool) loses its whole tree.

| Task | Trips |
|---|---|
| Purging all shadow copies: `vssadmin delete shadows /all`, `/for=X:` without `/oldest`, `wmic shadowcopy delete` | `shadow_delete` |
| Shrinking shadow storage below 1 GB | `shadow_delete` |
| `wbadmin delete catalog`; deleting backups without `-keepVersions:N` or `-deleteOldest` | `backup_delete` |
| Booting into Safe Mode with `bcdedit /set {current} safeboot minimal` (also reverted); turning recovery off on kiosks or VDI images | `boot_tamper` |
| Installing a driver with `sc create ... type= kernel` from a user-writable folder, or with the `.sys` outside System32\drivers | `byovd` |
| Snapshot rotation scripts: `lvremove vg/*snap*`, `zfs destroy pool@snap`, `btrfs subvolume delete .../snapshots/...` | `snapshot_delete` |
| `insmod` of a module built under `/home` or `/tmp` | `kernel_module` |
| Three or more of: stopping or disabling Defender or another security service, adding Defender exclusions, turning the firewall off (within a minute, from one program) | `defense_tamper` |

To allow them, either:

- add a ransomware-scope exclusion to the group's policy. A `command_line` exclusion with the script's path (`/usr/local/sbin/rotate-snapshots.sh`) or the exact command (`vssadmin delete shadows /for=E: /quiet`) matches when that script runs the command or that command runs. This works only when the tool runs from a system or program location: a script started by cron, a service or a scheduled task, or a tool in Program Files, `/usr/local/bin` or `/opt`. An `image` exclusion by full path allows a whole program. Keep command-line values specific: an exclusion matches any command line that contains it.
- or set the group's `ransomware_mode` to `report`, for servers whose admins run these routinely.

## Configuration

```yaml
ransomware:
  disabled: false
  report_only: false      # true: never kill, only report
  isolate: false          # true: also isolate the host on a confirmed detection
  canary_dirs: []         # globs; replace the defaults
  canary_names: []
  canary_visible: false   # true: plant !siem-canary.pdf in sight, no hidden attribute
  allow_images: []        # extra basenames the heuristics ignore
```

## Alerts

`decoders/ransomware_activity.yaml`. Three rules, each suppressed so one incident is one alert (the lines stay searchable in the log):

| Rule | Level | Fires on | Suppression |
|---|---|---|---|
| *Ransomware Activity On Endpoint* | critical | `ransomware.confirmed: true` (canary hits, confirmed heuristics, a canary found encrypted by the periodic check, precursors) | 10 min per host and `process.executable` |
| *Ransomware Canary File Changed* | high | `canary_changed` not confirmed (the periodic check found a canary changed in clear text or gone) | 1 h per host |
| *Ransomware Canary Retired* | medium | `canary_retired` | 24 h per host and canary |

## Testing

`TestPrecursorEndToEndWindows` (same job) runs a child that runs `cmd /c "vssadmin delete shadows /for=Z: /quiet"` (a volume that does not exist: harmless even elevated) and requires the child to be terminated with its tree and a `detection=precursor` kill line. `precursor_test.go` covers every precursor (IronChain's command lines verbatim), the everyday admin commands that stay quiet, the score threshold and window, the initiator walk (look-alikes, protected initiators, a parent gone, a reused PID), report_only, isolate, dedupe, the bcdedit revert, BYOVD drops and Safe Mode registration, on Windows and Linux rules alike, with fake process tables, kill and command runner. `TestRansomwareEndToEndWindows` (native-evidence Windows job) runs the real ETW sensor into the guard and requires four children to be terminated: one that encrypts and renames files, one that deletes a canary, one that overwrites 400 pre-existing documents in place with random bytes (under the user profile, not TEMP), and one that overwrites a canary in place. `guard_test.go` covers the thresholds, allowlist, window, entropy confirmation, canaries and responses with a fake kill; `inplace_test.go` the in-place rule (Linux and Windows path forms, ignored paths, self-created files, magic-header confirmation); `canary_encrypt_test.go` encrypted canaries (never retired, periodic check isolates); `winsensor/file_write_test.go` the write plumbing (resolution through the open, dedupe, nothing shipped). With root and BTF, `TestRansomwareEndToEnd` runs a child process that encrypts and renames files, then one that writes a canary, and requires both to be killed (CI runs it under sudo). `RANSOM_FP=10m -test.run TestFalsePositives` watches the host with kill off and prints any detection.
