# YARA on agents

Roadmap item 3.1. The agent ships its own YARA engine (`agent/internal/yara`), written in Go so the agent stays a static `CGO_ENABLED=0` binary on Linux amd64/arm64 and Windows. libyara and YARA-X both need cgo.

## Where rules run

| Path | Trigger | Result |
|---|---|---|
| On access (`agent/internal/yarascan`) | a file is created or changed under a watched directory | `yara_match` log line → alert "YARA Rule Matched On Endpoint (<severity>)" |
| `yara_scan` task (dashboard → YARA → Run Scan) | operator | task result with matches, `rule_errors`, `warnings` |
| `yara` live-response plugin | flow artifact | one row per match; a rule that does not compile is a row with `Error` |

On-access scanning uses every **enabled** rule on the YARA page. Heartbeats carry only the rule set's hash (`yara_rules_hash`); when it changes the agent fetches the rules from `POST /api/ingest/yara-rules` and retries every minute until that works. With no enabled rules nothing is scanned.

Watched directories (recursive, 4 levels, at most 4096 directories):

- Linux: `/tmp`, `/var/tmp`, `/dev/shm`, `/var/www`
- Windows: `%SystemRoot%\Temp`, `C:\Users\*\Downloads`, `C:\Users\*\AppData\Local\Temp`, `C:\Users\Public`, `C:\inetpub\wwwroot` (globs are expanded again every 5 minutes, so new profiles are picked up)

Agent config (`config.yaml`):

```yaml
yara:
  disabled: false          # true: no on-access scanning (tasks and live response still work)
  watch_paths: []          # replaces the defaults; globs allowed
  max_file_size_mb: 32
```

Limits: a file is scanned 2 s after its last write, once per (content, rule set); the queue holds 512 files and drops the rest (logged every 10 minutes); one scan stops after 30 s. Symlinks are not followed.

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
