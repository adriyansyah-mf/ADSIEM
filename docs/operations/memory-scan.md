# Process memory scanning

Roadmap item 3.5. `agent/internal/memscan` reads process memory on Linux (`/proc/<pid>/maps` + `/proc/<pid>/mem`) and Windows (`VirtualQueryEx` + `ReadProcessMemory`).

## YARA over memory (on demand)

- **YARA page → Run Scan → Target: Process memory**, with a PID (0 is every process). This creates a `memory_scan` task (`POST /api/yara-rules/scan-memory`) carrying the enabled rules.
- **Live response**: the artifacts `Linux.Memory.Yara` / `Windows.Memory.Yara` (plugin `memyara`, parameters `Pid`, `AnonOnly`).

Every readable region is scanned on its own, so `filesize` is the region size and the `pe`/`elf` modules see a mapped image when a region starts one. Regions larger than 16 MiB (heaps, arenas) are read in 16 MiB chunks that overlap by 64 KiB. At most 1 GiB is read per process. Match addresses are virtual (`$a@0x7f…`). `AnonOnly` skips libraries and mapped files. A scan of every process skips the agent, which holds the rules in memory itself. Processes the agent cannot open (Windows protected processes, or a process that exits mid-scan) are counted as skipped.

## Writable and executable memory

Memory that is writable **and** executable and not backed by a file is where shellcode, reflective DLLs and unpacked payloads live:

- Linux: anonymous, heap or stack mappings with `rwx`; also `memfd:` and deleted-file mappings.
- Windows: `MEM_PRIVATE` with `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY`.

The agent sweeps every process every 5 minutes and reports each such region once while it exists, as a `process_memory_rwx` line (`decoders/process_memory_rwx.yaml`). The rule *Writable And Executable Memory In Process* (medium) leaves out JIT runtimes (JVM, node, browsers, Electron, .NET, Teams, Slack). For a region it flags, run `*.Memory.Yara` on that PID. `Linux.Memory.RWX` / `Windows.Memory.RWX` list the regions on demand.

```yaml
memory_sweep:
  disabled: false
  interval_minutes: 5
```

## Testing

`memscan_test.go` reads the test's own memory: a YARA marker on the heap is found at a virtual address, a `PAGE_EXECUTE_READWRITE` / `PROT_EXEC` allocation is flagged, and limits are applied. It runs on Linux and on the Windows runner (`windows-agent.yml`, step *Process memory scan*). `TestScanOtherProcess` (root, CI under sudo) scans a separate process that holds a marker on its heap and in an RWX mapping, and checks that the sweep reports it.
