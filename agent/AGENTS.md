# AGENT (Go endpoint agent)

**Linux and Windows** (no macOS). Cross-compiled as a static binary (`CGO_ENABLED=0`, so no C libraries such as libyara); `.deb`/`.rpm` packaging + systemd unit live in `agent/packaging/`, the MSI in `agent/packaging/windows/`.

## STRUCTURE

```
agent/
├── cmd/agent/main.go        # entry — wires every subsystem in sequence
├── internal/
│   ├── config/              # YAML load/save + fsnotify watcher (bootstrap fields only)
│   ├── enrollment/          # first-run enroll → writes agent_id/token back to config.yaml
│   ├── tailer/              # log tailing (fixed + glob), rotation detect, tailer manager
│   ├── buffer/              # in-memory queue + disk spill of undelivered entries
│   ├── client/              # HTTP client (PostWithRetry / Post)
│   ├── heartbeat/           # 30s loop: log sources + FIM paths + task dispatch
│   ├── fim/                 # fsnotify watcher, SHA256, 2s debounce, 50-event batch
│   ├── hygiene/             # OS/patch/ports/disk snapshots
│   ├── procexec/            # eBPF execve monitor (bpf/ has .c + vendored headers)
│   ├── netwatch/            # eBPF connect/accept/bind/DNS + `ss` snapshot fallback
│   ├── detect/              # local threshold engine: keeps blocking when the server is down
│   ├── firewall/            # nftables gate: rule model, anti-lockout guard, engine
│   ├── yara/                # pure-Go YARA engine (language, pe/elf/math/hash/time modules)
│   ├── yarascan/            # on-access YARA scan of temp/download/web dirs with the server's rules
│   └── task/                # live response: collectors, yara, firewall tasks
└── packaging/               # build-deb.sh, build-rpm.sh, siem-agent.service, .spec
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Startup order / what runs | `cmd/agent/main.go` | enroll (if no token) → tailer mgr → config watch → hygiene → FIM → firewall engine → task runner → procexec → netwatch → heartbeat → sender |
| Sender backoff semantics | `cmd/agent/main.go` `senderLoop` | `>=500` re-queues entry; `>=300` logs + drops |
| Log-line codec | `internal/tailer/tailer.go` `encode`/`Decode` | `logType + "\x00" + rawMessage` |
| Glob rotation logic | `internal/tailer/tailer.go` `tailGlob` | first sight → seek EOF; new rotated file → read from start |
| Rebuild BPF object | `internal/procexec/bpf/execve.bpf.c`, `internal/netwatch/bpf/netwatch.bpf.c` | clang target bpf; objects are `go:embed`'d, **build fails without them** |
| Network telemetry | `internal/netwatch/netwatch.go` | connect/accept/bind/DNS → `linux_network_*`; needs tracefs + CAP_SYS_ADMIN |
| Netwatch fallback | `internal/netwatch/fallback.go` | `ss -tunapH` every 10s when eBPF cannot attach |
| Local detection engine | `internal/detect/detect.go` | sliding window + cooldown + block caps; emits `local_detection` |
| Local rule set | `internal/detect/defaults.go` | ssh_bruteforce, port_scan, windows_logon_bruteforce (4625 LogonType 3/10), webshell_upload — all disabled by default |
| Offline spill | `internal/buffer/spill.go` | undelivered entries to disk; replayed on boot **and** on reconnect |
| Firewall rule engine | `internal/firewall/engine.go` | nft backend + guard + JSON state; degrades to noop |
| Anti-lockout rules | `internal/firewall/guard.go` | refuses blocks covering SIEM IP / gateway / loopback |
| Firewall task handlers | `internal/task/firewall.go` | block_ip, unblock_ip, isolate_host, firewall_list, firewall_flush |
| Live-response collectors | `internal/task/collectors.go` | process_list, netstat, persistence_check, users_list, dmesg_tail, open_files, file_list, file_get |
| Live-response flows (Velociraptor-style) | `internal/task/flow.go` | long-polls `/api/agent/flows/poll`, runs sources sequentially, 500-row batches to `/update`, enforces timeout/max_rows, honours server cancel; a plugin ignoring ctx is abandoned after 5s |
| Flow plugins | `internal/task/plugins.go` | registry must match `PLUGINS` in `server-api/app/services/flow_artifacts.py`; plugins emit rows and must check ctx; glob/hash/yara never enter `/proc` `/sys` `/dev` unless the root is inside them (`/proc/kmsg` reads block forever) |
| Legacy task collectors | `internal/task/collectors.go`, `runner.go` | fixed task types via heartbeat (isolate/block-IP still use this path) |
| Windows firewall | `internal/firewall/netsh.go`, `internal/task/isolation_windows.go` | engine backend `netsh` (auto on Windows; `SIEM-FW-<id>-in/-out` rules, swept on expiry since Windows rules never time out) carries local detection blocks, server-synced rules and `block_ip` when `firewall.enabled`; isolation stays direct `netsh` (`SIEM-Isolate-*`, both directions) |
| YARA scans (on demand) | `internal/task/yara.go` | `yara_scan` task + `yara` flow plugin; each rule source compiles in its own namespace, a broken one is reported in `rule_errors`, the rest still scan |
| YARA engine | `internal/yara/` | checked against libyara 4.5 by `testdata/differential` (`gen_expected.py` regenerates `expected.json`); unsupported features are compile errors |
| On-access YARA | `internal/yarascan/` | heartbeat `yara_rules_hash` → `POST /api/ingest/yara-rules`; matches are `yara_match` lines (`decoders/yara_match.yaml`, `rules/yara_match_*.yaml`) |

## CONVENTIONS

- **`log/slog` only** (JSON handler) — no `fmt.Println`, no `log` stdlib package.
- **Everything degrades gracefully**: procexec, FIM, firewall, netwatch all `slog.Warn` and continue when unavailable — never `os.Exit` on those paths.
- **eBPF needs tracefs mounted**: containers do not mount it, and without it both procexec and netwatch fail with "neither debugfs nor tracefs are mounted". `demo/entrypoint.sh` mounts it; production hosts normally already have it.
- **netwatch drops its own process** (`comm=agent`). The agent's ingest traffic is one connect per shipped event; emitting it created a ~97k event/min feedback loop that buried real activity and built a 270k-deep Redis backlog.
- **BPF include root is `internal/`**: `netwatch.bpf.c` includes `"procexec/bpf/include/bpf/..."`, so its clang `-I` is `internal`, not `internal/procexec/bpf/include`.
- **Firewall fails open, not dead**: without `nft` or `CAP_NET_ADMIN` the engine swaps to a noop backend, reports `degraded` in `firewall_list`, and the agent keeps collecting. `SIEM_FW_DRY_RUN=1` forces that path and lists the commands it would have run.
- **Every firewall mutation is an event**: apply/remove/isolate/reject are pushed into the log buffer as `firewall_gate`, so they land in Elasticsearch like any other telemetry.
- **nft element syntax needs braces**: `add element ... set { <key> timeout 30s }`. Without the braces nft parses `timeout` as the next element and fails — `nftApplyArgv` owns that formatting.
- **Local rules must group by a regex, not a kv field, for syslog sources.** `auth.log` and Apache `access.log` are free text — `GroupBy: "host"` silently never matches and the rule looks installed but dead. `GroupExpr` exists for exactly this; `internal/detect/defaults_test.go` pins the patterns against real lab lines.
- **Local detection observes before delivery**, in `senderLoop`, so it keeps working while the server is unreachable. Moving that call onto the success path silently disables offline detection.
- **Local blocks reuse the firewall guard**: a rule that would block the SIEM IP, gateway or loopback is refused and the detection records `block_error` instead of blocking.
- **Expired rules are swept by the engine** (`Engine.Sweep`, every 15 s on a real backend). Windows rules never time out, and even nft's self-expiring elements stayed in the engine's applied set, where they counted against the detection cap (`BlockedEntries`) until local blocking silently stopped.
- **Windows local blocking needs both** `firewall.enabled: true` (the MSI's default config leaves it off: the engine is then noop and `block_ip` falls back to direct netsh) and `detect.enabled: true` with `windows_logon_bruteforce` in `detect.rules`.
- **Undelivered entries are spilled to disk** and replayed both at boot and when a send succeeds after a failure; without the reconnect replay they stay stranded until restart.
- **Config mutation is write-back**: after successful enrollment the agent rewrites `config.yaml`; log sources/FIM paths are then server-driven, not config-driven.
- **Buffer contract**: `Pop()` returns `(entry, ok)`; sender must re-`Push` on 5xx.
- **YARA behaviour follows libyara 4.5, quirks included**: regex matches stop at 1024 bytes, an undefined operand makes `and`/`or` false, a string only used as `$a at <literal>` is only recorded at that offset. Change semantics only with a differential case that shows libyara agrees.
- Module path is `github.com/siem-platform/agent`; deps are deliberately minimal (`cilium/ebpf`, `fsnotify`, `yaml.v3`). Firewall shells out to `nft`, no netlink library.

## ANTI-PATTERNS

- **Do not hardcode `http://`** for `server.url` — Go downgrades POST→GET across nginx's 301→405. See root AGENTS.md.
- **Do not add a `User=` hardening to the shipped systemd unit** without accepting that firewall and eBPF fail closed — the platform expects root.
- **Do not import `slices`/`maps` into `internal/firewall`** — it compiles under the module's Go directive and needs no generics.
- **Do not read guarded state with `RLock` and then call `Guard.Gateway()` inside it** — `Gateway()` takes the write lock to cache, and re-entering deadlocks (regression-tested in `engine_test.go`).
- **Do not commit new large binaries/bootstrap headers**; `bin/agent` and `include/bpf/vmlinux.h` are already committed artifacts and inflate the repo.
- **`make build` now compiles the eBPF object first** (target `bpf`, requires `clang`; fails with a clear message if absent). `make package-deb`/`package-rpm` depend on it too. The `.bpf.o` is gitignored — never commit it.
- **Windows/macOS hosts can still `go build ./...`** for editing; `hygiene/collector*.go` and `procexec/*.go` use `//go:build linux` with a no-op stub elsewhere.

## WINDOWS

- Same binary, `GOOS=windows` (`packaging/build-windows.sh` → zip with `install.ps1`/`uninstall.ps1`/`config.yaml`). Runs as the `SIEMAgent` service (`cmd/agent/service_windows.go`; `-install`/`-uninstall`), config and `agent.log` in `%ProgramData%\SIEMAgent`.
- Event logs: a log source path `eventlog:<channel>` (e.g. `eventlog:Security`) is read via `EvtSubscribe` (`internal/winevent`), future events only. Each event becomes one `EventID=<id> Channel="..." Key="value" ...` line — the contract for the `decoders/win_*.yaml` kv decoders; change `winevent.FormatXML` and those decoders together (`tests/agent/winevent_format_test.go`, `tests/worker/test_windows_decoding.py`).
- Live response: `plugins_windows.go` replaces pslist/netstat/users/persistence with PowerShell (`Get-CimInstance`, `Get-NetTCPConnection`, ...); `plugins_windows_extra.go` adds info (registry), eventlog (`winevent.Query`: channel + event_ids + hours, XPath built from validated args in `plugins_eventlog.go`), services and programs — used by the `Windows.*` artifacts in `server-api/app/artifacts/`. dmesg/open_files are unsupported. `tests/windows/smoke-msi.ps1` runs a flow with every Windows plugin on a real runner. Isolation/block-IP use `netsh advfirewall` rules named `SIEM-*`.
- Response on Windows (`internal/task/response_windows.go`, `quarantine_windows.go`): `kill_process` is `TerminateProcess` (no polite stop exists for arbitrary processes) and refuses PID 4, the agent and its parents, and critical images (lsass, csrss, wininit, services, svchost, ...) *only when they run from the system directory*, so a masquerading `lsass.exe` elsewhere can be killed. `quarantine_file` locks the file in place: a protected DACL granting only SYSTEM, owner moved to SYSTEM, original DACL/owner kept in `quarantine.json` for `restore_file`; it refuses `%SystemRoot%`, the agent's own directories and drive roots. `agent_integrity` is shared with Linux (`integrity.go`). Native tests: `response_windows_test.go`; `smoke-msi.ps1` runs kill/quarantine/restore through the installed service.
- No eBPF/process-exec stream and no package hygiene on Windows — use Sysmon (`eventlog:Microsoft-Windows-Sysmon/Operational`) or 4688 for process creation.
