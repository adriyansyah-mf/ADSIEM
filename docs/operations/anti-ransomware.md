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

When a canary changed, the agent reads its new content. If it looks encrypted (first 4 KB at 7.2 bits per byte or more, or the canary text replaced by a first kilobyte that is, and no known file header; the canary itself is hex text, about 4 bits per byte), the change is ransomware:

- with a process (a file event): the process tree is killed as for any canary hit;
- without one (the periodic check): `detection=canary_changed confirmed=true`, so the critical rule fires, and the host is isolated through the firewall engine when `isolate` (or the policy's `ransomware_isolate`) is set: `response=isolated`, `Isolated=true`. Otherwise `response=none`.

A canary changed **in clear text** or removed 3 times within 24 hours (by either path) is **retired**: the agent stops planting it in that spot for 24 hours and reports `detection=canary_retired` once, with the process if one is known. That is a legitimate tool rewriting the directory, not ransomware, which is stopped on the first hit. An encrypted canary never counts toward retirement, so repeated attacks (or repeated test runs) cannot switch protection off. Retirement lives in memory and resets when the agent restarts.

## Bulk-encryption heuristics (Linux and Windows)

Per process, over a one-minute window of file events:

| Detection | Fires when |
|---|---|
| `extension_change` | 20 or more renames to a new extension, at least 70% of them to the same one (`.locked`, `.enc`, a random suffix) |
| `mass_modify` | 200 or more files written across 10 or more directories, with 50 or more deletes or renames |
| `inplace_modify` | 50 or more files that existed before written across 3 or more directories, no rename needed (each file encrypted over itself) |

For `inplace_modify`, files the process created in the window don't count (on Linux an open with `O_CREAT` counts as a create, so unpacking an archive is not "in place"; Linux in-place encryptors open with `O_RDWR`), and neither do writes under caches, temp and profiles: `AppData\Local`, `AppData\LocalLow`, cache-like directories and Mozilla/Thunderbird profiles under `AppData\Roaming`, `Temp`/`tmp`, `C:\Windows`, `Program Files`, `ProgramData`, `/var/cache`, `/var/log`, `~/.cache`, browser profiles under `~/.config` and `~/.mozilla`, `/proc`, `/sys`, `/dev`, `/run`.

A heuristic hit is **confirmed** only if most of the newest files the process wrote (up to 3, first 4 KB each) look encrypted: an entropy of at least 7.2 bits per byte **and** no known file header. Office documents (`PK\x03\x04`, OLE `\xD0\xCF\x11\xE0`), PDF, JPEG, PNG, GIF, RTF, zip/7z/rar/gz/bz2/xz/zstd/cab, MP4/MOV (`ftyp`), MKV, RIFF, Ogg, FLAC, MP3, TIFF, PSD, PE, ELF and SQLite files are high entropy on their own but start with their magic; encryption replaces it. So a photo editor saving 60 JPEGs or Office saving documents stays unconfirmed, while the same files encrypted in place confirm. A file without a known header (txt, csv, ...) confirms on entropy alone. If the first look does not confirm, the files are sampled once more 300 ms later (the newest may still be being written). Unconfirmed hits are logged (`confirmed=false`) but raise no alert and kill nothing. Package managers, git, rsync, backup tools, container engines and build tools are excluded. Add your own with `allow_images`. Interpreters such as python and node are deliberately not excluded.

## Response

On a canary hit or a confirmed heuristic, the agent stops the process and its descendants and reports `response=killed` with `Killed=<n>`. On Linux: SIGSTOP the tree, then SIGKILL. On Windows: `TerminateProcess` on the process, then its descendants (from a process snapshot). It never kills PID 1, itself, systemd, init or sshd (`response=kill_refused`); on Windows it also refuses System, the agent's ancestors (the service host) and critical processes running from System32 (csrss, lsass, services, svchost, wininit, winlogon, smss, ...), reported as `response=kill_failed` with the reason. With `isolate: true` it also isolates the host through the firewall engine, which needs `firewall.enabled`.

A confirmed detection without a process (an encrypted canary found by the periodic check) has nothing to kill: the host is isolated when `isolate` is set (`response=isolated`), otherwise `response=none`.

### Windows writes

Kernel-File write events (event 16, keyword `WRITE` 0x200) carry no file name, only the `FileObject` of the open they write through. The sensor subscribes to them in the same session as the opens (event 12), but only when the guard is running, and resolves each write through the `FileObject -> name` map the opens fill (bounded at 16,384 objects; a write through an unknown object is dropped). Writes go to the guard only, as `action=write` events, never as SIEM lines: what is shipped to the server is unchanged. A file written in many chunks is one event per process and file a minute (a bounded set of 16,384). Writes by System (PID 4: the lazy writer and paging I/O) and by the agent itself are dropped.

So on Windows the heuristics see creates, writes, renames and deletes: they catch rename-to-new-extension, write-a-copy-then-delete and in-place ransomware, and a canary overwritten in place is a canary hit with its process. Windows installers, servicing, Defender, OneDrive and its updater (`OneDriveSetup.exe`, which writes hundreds of PNG tiles), robocopy, the search indexer and build tools are allowlisted (case-insensitively). The Windows feed needs the ETW sensor's file group: with `etw.mode: auto` and Sysmon installed, or `etw.disabled_events: [file]`, Windows is back to canary checks without a process to stop.

Measured with the real sensor: a test encryptor was stopped after 20 of 400 files. On a busy desktop, 90 seconds of normal activity (2,107 file events) gave no detections, and a full `go build -a` gave one unconfirmed detection before build tools were allowlisted.

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
| *Ransomware Activity On Endpoint* | critical | `ransomware.confirmed: true` (canary hits, confirmed heuristics, a canary found encrypted by the periodic check) | 10 min per host and `process.executable` |
| *Ransomware Canary File Changed* | high | `canary_changed` not confirmed (the periodic check found a canary changed in clear text or gone) | 1 h per host |
| *Ransomware Canary Retired* | medium | `canary_retired` | 24 h per host and canary |

## Testing

`TestRansomwareEndToEndWindows` (native-evidence Windows job) runs the real ETW sensor into the guard and requires four children to be terminated: one that encrypts and renames files, one that deletes a canary, one that overwrites 400 pre-existing documents in place with random bytes (under the user profile, not TEMP), and one that overwrites a canary in place. `guard_test.go` covers the thresholds, allowlist, window, entropy confirmation, canaries and responses with a fake kill; `inplace_test.go` the in-place rule (Linux and Windows path forms, ignored paths, self-created files, magic-header confirmation); `canary_encrypt_test.go` encrypted canaries (never retired, periodic check isolates); `winsensor/file_write_test.go` the write plumbing (resolution through the open, dedupe, nothing shipped). With root and BTF, `TestRansomwareEndToEnd` runs a child process that encrypts and renames files, then one that writes a canary, and requires both to be killed (CI runs it under sudo). `RANSOM_FP=10m -test.run TestFalsePositives` watches the host with kill off and prints any detection.
