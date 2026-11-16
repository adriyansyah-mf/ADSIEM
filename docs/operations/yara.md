# YARA on agents

Roadmap item 3.1. The agent ships its own YARA engine (`agent/internal/yara`), written in Go so the agent stays a static `CGO_ENABLED=0` binary on Linux amd64/arm64 and Windows. libyara and YARA-X both need cgo.

## Where rules run

| Path | Trigger | Result |
|---|---|---|
| On access (`agent/internal/yarascan`) | a file is created or changed under a watched directory; a program, script or container a file sensor saw written anywhere; a program starting; a rescan after new rules or hashes (see [Real-time coverage](#real-time-coverage)) | `yara_match` log line → alert "YARA Rule Matched On Endpoint (<severity>)"; with `yara_action: quarantine` the file is also locked |
| `yara_scan` task (dashboard → YARA → Run Scan) | operator | task result with matches, `rule_errors`, `warnings` |
| `yara` live-response plugin | flow artifact | one row per match; a rule that does not compile is a row with `Error` |

On-access scanning uses every **enabled** rule on the YARA page. Heartbeats carry only the rule set's hash (`yara_rules_hash`); when it changes the agent fetches the rules from `POST /api/ingest/yara-rules` and retries every minute until that works. With no enabled rules nothing is scanned.

Watched directories (recursive, 4 levels, at most 4096 directories):

- Linux: `/tmp`, `/var/tmp`, `/dev/shm`, `/var/www`, `/srv/www`, `/home/*/Downloads`
- Windows: `%SystemRoot%\Temp`, `C:\Users\*\Downloads`, `C:\Users\*\Desktop`, `C:\Users\*\AppData\Local\Temp`, `C:\Users\Public`, `C:\inetpub\wwwroot` (globs are expanded again every 5 minutes, so new profiles are picked up)

Large trees (`C:\ProgramData`, `/root`, `/opt`) are not watched: they would use up the 4096 directories. The file sensors cover them, and every other folder, for programs and scripts.

Agent config (`config.yaml`):

```yaml
yara:
  disabled: false          # true: no on-access scanning (tasks and live response still work)
  watch_paths: []          # replaces the defaults; globs allowed
  max_file_size_mb: 32
```

Limits: a file is scanned 2 s after its last write (a file still growing is waited for, up to about 30 s), once per (content, rule set, known-malware set); one scan stops after 30 s. Symlinks are not followed. A file over `max_file_size_mb` is hashed whole and its first `max_file_size_mb` and last quarter of that are scanned (`part=head` / `part=tail` in the line); files over 512 MiB are skipped.

## Real-time coverage

Files reach the scanner four ways. Each goes through every engine: known-malware hashes, TLSH variants, static ML, YARA, and what is inside containers.

| Way | Linux | Windows | `trigger` |
|---|---|---|---|
| Watched directories | inotify, the folders above | ReadDirectoryChangesW, the folders above | `on_access` |
| File sensors, anywhere on disk | eBPF (`linsensor`): create, write, rename | ETW file events (`winsensor`) | `on_access` |
| A program starting | before it runs: the fanotify helper holds the exec until the scan answers (`exec_check`); after, for what it did not see: the eBPF exec sensor, read through `/proc/<pid>/exe` (`exec`) | right after it starts: the ETW process start (`exec`) | `exec_check`, `exec` |
| New rules or known-malware hashes | rescan of files changed in the last 7 days in the watched directories (at most 5000), and once at agent start | same | `rescan` |

**What a sensor event scans.** Outside the watched directories only files that can run or carry what runs: programs, scripts, shortcuts, macro documents, archives and disk images, recognised by name or first bytes (`MZ`, `\x7fELF`, `#!`, `PK`, OLE, `<?php`, …). Logs, databases, journals and partial downloads (`.crdownload`, `.part`) are never read. Files the OS or a package manager writes in bursts are not taken from the sensors either: the system folders (`/usr`, `/bin`, `/lib*`, `%SystemRoot%`, Program Files), `node_modules`, `site-packages`, `.git`, Go/Cargo/Maven/Gradle caches, browser caches and profiles, and container storage (`/var/lib/docker`, `containerd`). A program from there is still scanned when it starts, and a project a developer installs is scanned by the project scanner. Each match line names the writer: `writer_pid`, `writer_image`.

**Before a program runs (Linux, group policy `exec_scan`, default on).** The fanotify helper sends a program outside the system folders (`/usr`, `/bin`, `/sbin`, `/lib*`, `/snap`, `/nix/store`) to the agent and waits for the verdict, at most 3 s; then it runs and the scan finishes in the background (a quarantine then stops it). A program the scan quarantined (known-malware block, `ml_action: block`, `yara_action: quarantine`) gets "Operation not permitted". The verdict is kept per inode and change time, so the next start is instant. At most three programs wait for a scan at once; the fourth runs unchecked, so the host's other starts never queue behind scans. Windows has no veto before a program runs: each new program outside `%SystemRoot%` (except `Windows\Temp`) and Program Files is scanned right after it starts, and quarantining it stops it.

**Queue.** Programs and scripts and programs starting go to a queue of 2048 that is always emptied first (from a watched folder a file without an extension counts as a program; from a sensor only the extension does, the first bytes decide later); other files to a queue of 512; rescans wait behind both and never take their place. A file that finds its queue full is left unscanned. From a watched folder or a program starting it is counted as lost: `sensor_health.file_scan.lost` in the heartbeat raises the "events lost" sensor alert, so flooding a watched folder to hide a payload is seen. A full queue from a sensor burst elsewhere (a large build) is only logged.

## Quarantine on a match

Group policy **YARA match on a file** (`yara_action`, see [policies](policies.md)):

- `detect` (default): the alert only, `action=detected` in the line.
- `quarantine`: a match whose rule severity is at least `yara_quarantine_level` (`critical` by default, or `high`) locks the file where it is and stops the programs running it, as `quarantine_file` does (restorable from the dashboard). A file inside an archive locks the archive. The line says `action=quarantined`, or `action=detected error="..."` when the file could not be locked (a protected system path, for example).

When a file sensor saw who wrote the file and that program itself runs from a temp, downloads or shared-memory folder (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `~/Downloads`, `%TEMP%`, `Windows\Temp`, `Users\Public`), it is stopped as the dropper: `writer_stopped=true`. A program installed elsewhere (a browser, an archiver, `explorer.exe`) is left running and only named. `kill_process`'s guards apply (never pid 1/4, the agent, its ancestors, or critical system processes).

Exclusions with the YARA scope leave a path out of YARA and of the pre-exec scan.

### Inside containers

Most malware arrives wrapped, so on-access scanning also opens what a file contains (`agent/internal/unpack`), in memory, and checks every file inside with the same engines: known-malware hashes, the YARA rules and the static ML check.

| Container | What is checked |
|---|---|
| ZIP (also docx, xlsx, jar, apk) | every entry; nested archives too |
| ISO 9660 disk images | every file (ISO names; UDF-only images are not opened) |
| gzip, tar | the content / every entry |
| Windows shortcut (LNK) | its target, working directory and arguments, as text (`lnk-target.txt`): the command a malicious shortcut runs |
| HTML smuggling | base64 blobs of 1 KB or more that decode to a program, an archive, a shortcut or an Office/MSI file (`html-blob-N`) |

A file inside is reported as `outer|inner`, for example `C:\Users\bob\Downloads\invoice.zip|invoice.pdf.exe` (`file.path` in the alert). Blocking (known-malware block, `ml_action: block`) quarantines the outer file. Exclusions by path still match: `C:\Tools\` covers `C:\Tools\x.zip|a.exe`.

Bounds: 3 levels of nesting, 1000 files, 64 MB per file, 256 MB per container, compression ratio 200 (archive bombs). Encrypted entries, 7z and RAR are not opened (logged at debug level). `yarascan.Options.NoUnpack` turns it off.

## Built-in rule pack

`yara/builtin/*.yar` ships with the server (copied into the server-api image) and is synced into the YARA rules at every start (`server-api/app/services/yara_builtin.py`): one rule per file, origin `builtin`, named `builtin/<file>`, **enabled by default**, so agents scan new and changed files in the watched directories with no rule written by hand. An upgrade updates their content; an analyst's enable/disable is kept. They cannot be edited or deleted in place (they would come back on the next start): disable one, or save a copy under another name and change that. The 7 rules the server used to keep inline (seeded with *Seed built-ins*) are removed when still unchanged.

| File | Rules |
|---|---|
| `test_eicar.yar` | EICAR test file (prove on-access scanning end to end) |
| `hacktool_credential_theft.yar` | Mimikatz, LaZagne, LSASS dump scripts (comsvcs MiniDump, procdump) |
| `hacktool_c2_frameworks.yar` | Cobalt Strike beacon strings, Meterpreter, Sliver |
| `webshells.yar` | PHP eval/exec of request input, known PHP shells (c99, r57, b374k, WSO), ASPX China Chopper style, JSP Runtime.exec |
| `ransomware.yar` | ransom notes, scripts deleting shadow copies, backups and boot recovery |
| `coinminers.yar` | XMRig and its configs, miner dropper scripts |
| `scripts_loaders.yar` | PowerShell download cradles, AMSI bypass, reverse shell one-liners |

All are written for ADSIEM (no third-party rules) and use only plain strings and regexes. `agent/internal/yara/builtin_test.go` compiles every file with the agent's engine, requires a match on a sample for each rule, and no match on benign look-alikes or system binaries (`sh`, `bash`, `python3`, `curl`, `ssh`, `openssl`, …). To try it on a host: create the EICAR file in a watched directory and look for the `yara_match` alert.

## Community rule pack

`yara/community/*.yar`: 2,845 rules from [YARA-Forge](https://github.com/YARAHQ/yara-forge) (release 20261101, core package), synced like the built-in pack (named `community/<set>`, enabled by default, not editable in place). Only rule sets whose licence allows use in a commercial product are packed:

| Licence | Sets |
|---|---|
| MIT, Apache-2.0, BSD | DitekSHen, ESET, FireEye Red Team, GCTI, Trellix ARC, Volexity, WithSecure Labs, Telekom Security, Elceef |
| Detection Rule License 1.1 (use in products allowed, attribution kept in each rule's meta and the file header) | Signature Base, SEKOIA, Synacktiv, Dr4k0nia, Cod3nym |

Left out: sets with no licence (Malpedia among them), GPL sets (CAPE, craiu), and rules the agent's engine does not compile (modules `dotnet`, `magic`, `console`; 79 rules). `MANIFEST.json` lists every set with its source commit, licence and counts.

False positives: the pack was run over 622,261 known-good files (`/usr/bin`, `/usr/sbin`, `/usr/lib`, Python packages, .NET SDK, PowerShell 7, mingw, Steam); 7 rules matched, all on offensive tools installed on the build machine (pypykatz, Masky, CrackMapExec, penelope, iodine, socat, nping). The `socat` and `nping` rules were dropped (common admin tools); the others are correct detections and kept.

Regenerate (from `agent/`):

```sh
go run ./cmd/yarapack -forge yara-rules-core.yar -out ../yara/community -release <YARA-Forge release> \
  -benign /usr/bin,/usr/lib,... -drop SEKOIA_Hacktool_Socat_Strings,SEKOIA_Tool_Nping_Strings
```

Scanning thousands of rules is made affordable by the engine's prefilter (`agent/internal/yara/prefilter.go`): every string gets a 2–4 byte "atom" it must contain; one pass over the data finds the atoms present, and only strings whose atom is there are searched, at the atom's positions. A string that matches always has its atom, so results do not change (differential tests against libyara, `TestPrefilterGivesTheSameMatches`). With the community pack, a 10 MB .NET DLL scans in about 1 s instead of 13.6 s.

## Alerts

Each match is a `yara_match` line decoded by `decoders/yara_match.yaml` (`yara.rule`, `yara.namespace`, `yara.severity`, `yara.tags`, `yara.strings`, `file.path`, `file.hash.sha256`, `file.size`). Four Sigma rules (`rules/yara_match_{critical,high,medium,low}.yaml`) raise the alert. Severity comes from the YARA rule's meta:

1. `severity = "low" | "medium" | "high" | "critical"`
2. otherwise `score` (0–100, as in signature-base): ≥80 critical, ≥60 high, ≥40 medium, >0 low
3. otherwise high

Alerts are deduplicated per title and host for 30 minutes like every other alert, so several matches on one host in that window raise one alert; each match is still its own log line.

## Language support

The engine is checked against libyara 4.5.4: `agent/internal/yara/testdata/differential` holds rules and inputs (`cases*.yaml`), libyara's results (`expected.json`, made by `gen_expected.py`) and binary fixtures. `TestDifferential` compares every match offset and length; `TestModuleData` compares every declared `pe`/`elf` field.

Supported:

- strings: text with `nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`/`xor(a-b)`, `base64`/`base64wide` (custom alphabets); hex with `??`, nibbles, `~`, jumps `[n]`, `[n-m]`, `[n-]`, alternatives; regex with `/i`, `/s`, `nocase`, `wide`, `fullword`
- conditions: `and or not defined`, arithmetic and bitwise operators, comparisons, `contains icontains startswith istartswith endswith iendswith iequals matches`, `#a @a[i] !a[i]`, `at`, `in`, `#a in (..)`, `filesize`, `entrypoint`, `(u)int8/16/32(be)`, `any/all/none/N/N% of (them | $a* | rule sets)`, `for .. of`, `for .. in` (ranges, enumerations, module arrays and dictionaries), rule references, `global` and `private` rules, tags and meta
- modules: `pe` (headers, sections, data directories, imports and exports with details, `imports()`, `exports()`, `exports_index()`, `section_index()`, `rva_to_offset()`, `is_dll/is_32bit/is_64bit()`, `imphash()`, `overlay`, `pdb_path`), `elf` (headers, sections, segments, dynamic, symtab, dynsym), `math`, `hash`, `time`

Not supported, and a **compile error** (the rule is skipped and reported, never silently wrong):

- `include`, and the `dotnet`, `magic`, `cuckoo`, `console` and `string` modules
- `pe` signatures (`number_of_signatures`, `signatures`, `is_signed`), `rich_signature`, resources, `version_info`, delayed imports; `elf.telfhash()`, `elf.import_md5()`
- `pe.imphash()` is **undefined** when the file imports by ordinal (libyara resolves some ordinals to names from built-in tables; the engine does not)

libyara behaviours the engine copies on purpose: regex matches are cut at 1024 bytes; an undefined operand makes `and`/`or` false (only `not` keeps it undefined); a string used only as `$a at <number>` is recorded only at that offset; `for .. in (1..#a)` with no matches is false for every quantifier.

## Performance

`go test ./internal/yara -bench Scan` (60 mixed rules, Intel Core Ultra 7 155U): about 110 MB/s on random data and 30 MB/s on text dense with rule prefixes. A pathological string stops at a step budget with a warning instead of running for minutes (`TestStepBudget`). Scans are bounded by the context: the on-access scanner allows 30 s per file, a task 15 minutes.

## Changing the engine

Add a case to `cases.yaml` (or `cases_modules.yaml`) first, regenerate with libyara and only then change Go code:

```sh
uv venv /tmp/yref && uv pip install --python /tmp/yref/bin/python yara-python pyyaml
/tmp/yref/bin/python agent/internal/yara/testdata/differential/gen_expected.py
cd agent && go test ./internal/yara/
```

Fuzz targets: `go test ./internal/yara -run '^$' -fuzz FuzzCompile` and `-fuzz FuzzScan`.

## Offline start

The last rule set the server sent is kept in `<state_dir>/yara_rules.json` (0600, SHA-256 checksum over the rules) and compiled when the agent starts, so on-access scanning works before the server answers. When the server reports no rules, the cache is removed with them. A file that fails its checksum is ignored and logged. Tests: `internal/yarascan/cache_test.go`.
