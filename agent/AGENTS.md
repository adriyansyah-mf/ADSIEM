# AGENT (Go endpoint agent)

**Linux-only.** No Windows/macOS build. Cross-compiled as static binary; `.deb`/`.rpm` packaging + systemd unit live in `agent/packaging/`.

## STRUCTURE

```
agent/
├── cmd/agent/main.go        # entry — wires every subsystem in sequence
├── internal/
│   ├── config/              # YAML load/save + fsnotify watcher (bootstrap fields only)
│   ├── enrollment/          # first-run enroll → writes agent_id/token back to config.yaml
│   ├── tailer/              # log tailing (fixed + glob), rotation detect, tailer manager
│   ├── buffer/              # in-memory queue, re-queue on 5xx, drop on 4xx
│   ├── client/              # HTTP client (PostWithRetry / Post)
│   ├── heartbeat/           # 30s loop: log sources + FIM paths + task dispatch
│   ├── fim/                 # fsnotify watcher, SHA256, 2s debounce, 50-event batch
│   ├── hygiene/             # OS/patch/ports/disk snapshots
│   ├── procexec/            # eBPF execve monitor (bpf/ has .c + vendored headers)
│   └── task/                # live response: collectors, yara, isolation (iptables)
└── packaging/               # build-deb.sh, build-rpm.sh, siem-agent.service, .spec
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Startup order / what runs | `cmd/agent/main.go` | enroll (if no token) → tailer mgr → config watch → hygiene → FIM → task runner → procexec → heartbeat → sender |
| Sender backoff semantics | `cmd/agent/main.go` `senderLoop` | `>=500` re-queues entry; `>=300` logs + drops |
| Log-line codec | `internal/tailer/tailer.go` `encode`/`Decode` | `logType + "\x00" + rawMessage` |
| Glob rotation logic | `internal/tailer/tailer.go` `tailGlob` | first sight → seek EOF; new rotated file → read from start |
| Rebuild BPF object | `internal/procexec/bpf/execve.bpf.c` | clang target bpf; object is `go:embed`'d, **build fails without it** |
| Isolate/block-IP (iptables) | `internal/task/isolation.go` | needs root |
| Live-response flows (Velociraptor-style) | `internal/task/flow.go` | long-polls `/api/agent/flows/poll`, runs sources sequentially, 500-row batches to `/update`, enforces timeout/max_rows, honours server cancel; a plugin ignoring ctx is abandoned after 5s |
| Flow plugins | `internal/task/plugins.go` | registry must match `PLUGINS` in `server-api/app/services/flow_artifacts.py`; plugins emit rows and must check ctx; glob/hash/yara never enter `/proc` `/sys` `/dev` unless the root is inside them (`/proc/kmsg` reads block forever) |
| Legacy task collectors | `internal/task/collectors.go`, `runner.go` | fixed task types via heartbeat (isolate/block-IP still use this path) |
| YARA scans | `internal/task/yara.go` | |

## CONVENTIONS

- **`log/slog` only** (JSON handler) — no `fmt.Println`, no `log` stdlib package.
- **Everything degrades gracefully**: procexec, FIM, isolation all `slog.Warn` and continue when unavailable — never `os.Exit` on those paths.
- **Config mutation is write-back**: after successful enrollment the agent rewrites `config.yaml`; log sources/FIM paths are then server-driven, not config-driven.
- **Buffer contract**: `Pop()` returns `(entry, ok)`; sender must re-`Push` on 5xx.
- Module path is `github.com/siem-platform/agent`; deps are deliberately minimal (`cilium/ebpf`, `fsnotify`, `yaml.v3`).

## ANTI-PATTERNS

- **Do not hardcode `http://`** for `server.url` — Go downgrades POST→GET across nginx's 301→405. See root AGENTS.md.
- **Do not add a `User=` hardening to the shipped systemd unit** without accepting that isolate/block-IP and eBPF fail closed — the platform expects root.
- **Do not commit new large binaries/bootstrap headers**; `bin/agent` and `include/bpf/vmlinux.h` are already committed artifacts and inflate the repo.
- **`make build` now compiles the eBPF object first** (target `bpf`, requires `clang`; fails with a clear message if absent). `make package-deb`/`package-rpm` depend on it too. The `.bpf.o` is gitignored — never commit it.
- **Windows/macOS hosts can still `go build ./...`** for editing; `hygiene/collector*.go` and `procexec/*.go` use `//go:build linux` with a no-op stub elsewhere.

## WINDOWS

- Same binary, `GOOS=windows` (`packaging/build-windows.sh` → zip with `install.ps1`/`uninstall.ps1`/`config.yaml`). Runs as the `SIEMAgent` service (`cmd/agent/service_windows.go`; `-install`/`-uninstall`), config and `agent.log` in `%ProgramData%\SIEMAgent`.
- Event logs: a log source path `eventlog:<channel>` (e.g. `eventlog:Security`) is read via `EvtSubscribe` (`internal/winevent`), future events only. Each event becomes one `EventID=<id> Channel="..." Key="value" ...` line — the contract for the `decoders/win_*.yaml` kv decoders; change `winevent.FormatXML` and those decoders together (`tests/agent/winevent_format_test.go`, `tests/worker/test_windows_decoding.py`).
- Live response: `plugins_windows.go` replaces pslist/netstat/users/persistence with PowerShell (`Get-CimInstance`, `Get-NetTCPConnection`, ...); dmesg/open_files are unsupported. Isolation/block-IP use `netsh advfirewall` rules named `SIEM-*`.
- No eBPF/process-exec stream and no package hygiene on Windows — use Sysmon (`eventlog:Microsoft-Windows-Sysmon/Operational`) or 4688 for process creation.
