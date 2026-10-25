# Linux sensor (file, module, ptrace, privilege, memfd, exit)

Roadmap item 3.2. `agent/internal/linsensor` adds the host telemetry that `procexec` (exec) and `netwatch` (network) do not cover. One eBPF object (`bpf/linsensor.bpf.c`) attaches to syscall and sched tracepoints (no kprobes); like procexec it needs root (CAP_BPF/CAP_SYS_ADMIN), tracefs and a BTF kernel (5.8+), and the agent runs without it when it cannot load.

| Log type | What | Volume control |
|---|---|---|
| `linux_file_event` | successful writes (`openat`/`open`/`creat` for writing), renames, deletes and `rmdir` | per process: 30 events a minute, the rest counted into one `action=summary` line; duplicates dropped; `/proc /sys /dev /run /var/run` skipped (`/dev/shm` kept) |
| `linux_kernel_module` | `finit_module` (`action=load`, Module is the file), `init_module` (`load_memory`), `delete_module` (`unload`) | none needed |
| `linux_ptrace` | attach, seize, poke text/data/user, setregs | same tracer/target/request once a minute |
| `linux_privilege_change` | `set*uid`/`set*gid` to 0 and `capset` by a caller whose real uid is not 0 (`User`/`EUID` are its ids *before* the call) | none needed |
| `linux_memfd_create` | `memfd_create` | per image and name once per 10 minutes |
| `linux_fileless_exec` | exec of a memfd or of a deleted file (`Image=/memfd:<name>`, `ExecPath` as given to exec) | always reported |
| `linux_process_exit` | thread-group leader exit, `ExitCode` or killing `Signal` | none (about as many as execs) |

Only syscalls that succeeded are reported (arguments are stashed at `sys_enter`, the record is written at `sys_exit`). Relative paths are resolved **in the kernel** from the caller's working directory or dirfd, and the executable's full path is captured at exec, so short-lived processes (`mv`, `rm`, droppers) still get `TargetFilename` and `Image` right after they have exited. Paths deeper than 16 components, or with a component over 127 bytes, are cut.

Measured on a busy desktop (browser, IDE) for 60 s: about 380 exit, 85 file (from 1,030 raw file events), 8 memfd and 1 privilege lines a minute, no ring-buffer loss.

## Rules

Decoders: `decoders/linux_{file_event,kernel_module,ptrace,privilege_change,memfd_create,fileless_exec,process_exit}.yaml`. File events carry Sigma-native `TargetFilename`, `SourceFilename` and `Image`; `worker/worker/sigma_logsource.py` routes them to the `linux` `file_event` (create/write), `file_delete` and `file_rename` categories, so SigmaHQ linux file rules apply unmodified.

Shipped rules: Fileless Process Execution (critical), Process Injection Via Ptrace (high, debuggers excluded), Unexpected Privilege Change To Root (high, setuid tools excluded), Kernel Module Loaded (medium), Kernel Module Loaded From Memory (high), LD Preload Hijack File Written (high), SSH Authorized Keys Modified (medium).

## Configuration

```yaml
linux_sensor:
  disabled: false
  disabled_events: []   # any of: file, module, ptrace, privilege, memfd, exit
```

Fileless exec cannot be switched off. The sensor never reports the agent's own process; it learns its kernel-side pid with a `prctl` handshake at start, which also works when the agent runs in a container. In a container the agent still needs the host pid namespace (`--pid=host`) for the `/proc` lookups of processes that started before it.

## Testing

`internal/linsensor/processor_test.go` covers decoding, path resolution, budgets and deduplication without a kernel. The end-to-end test loads the object into the running kernel and drives real file, memfd, ptrace, setuid and exit activity from child processes; CI runs it under `sudo`. Locally:

```sh
cd agent && make bpf
CGO_ENABLED=0 go test -c -o /tmp/linsensor.test ./internal/linsensor/
docker run --rm --privileged --pid=host -e LINSENSOR_E2E=1 -v /tmp/linsensor.test:/t:ro debian:bookworm-slim \
  sh -c 'mount -t tracefs nodev /sys/kernel/tracing; /t -test.run TestSensorEndToEnd -test.v'
```

`LINSENSOR_VOLUME=60s` with `-test.run TestSensorVolume` prints the line rate per log type for the host.
