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

## Credential access, memory injection and persistence (agent 1.13, the Linux side of the Windows sensor's process access and registry watcher)

| Line | Source | Means |
|---|---|---|
| `linux_process_access action=vm_read / vm_write` | `process_vm_readv` / `process_vm_writev` that succeeded | a program read or wrote another process's memory (own memory left out) |
| `linux_process_access action=mem_read / mem_write` | open of `/proc/<pid>/mem` (read-only opens of it are passed by the kernel program; `/proc/self/mem` is not) | the same through procfs; writes there used to be dropped with the rest of `/proc` |
| `linux_file_event action=read TargetFilename=/etc/shadow` | read-only open of `/etc/shadow` or `/etc/gshadow` (the only read-only opens the kernel program passes besides `/proc/<pid>/mem`) | password hashes read |

The same reader, target and action (or reader and file) is sent once per 10 minutes. `disabled_events: [access]` turns all three off. Persistence needs no new telemetry: every write to cron, systemd, boot scripts, shell profiles, sudoers / PAM, udev / autostart / MOTD and account files is already a `linux_file_event`; the rules below look at them.

Rules: credential process memory read (sshd, sudo, su, login, keyrings, ssh-agent; critical), memory written into another process (high), `/etc/shadow` read by a program outside login / sudo / account tools (high), cron / systemd unit / user unit / timer, boot scripts, shell startup files by a non-editor, sudoers / PAM files and modules, autostart / udev / update-motd.d, account files outside account tools (package managers left out everywhere), LibreOffice starting a shell, downloads into `/tmp` / `/var/tmp` / `/dev/shm` (curl, wget, Python / Perl one-liners), `chmod +x` there or a program started from there. Memory access and ptrace also appear in the alert's Process tree.

## Tamper checks

Root can blind an eBPF sensor without stopping the agent, so the agent's heartbeat, stop and integrity alerts would not fire. `internal/linsensor/health.go` checks the sensor itself and reports `linux_sensor_health` lines (`decoders/linux_sensor_health.yaml`):

| Check | How | Line | Rule |
|---|---|---|---|
| Exclusion map | Every 30 s the `self` map (the agent's tgid, whose events the kernel skips) is re-read. Another tgid there (`bpftool map update name self ...`) hides that process: the map is restored and reported. | `event=self_map_overwritten expected_tgid= found_tgid= restored=` | SIEM Agent Sensor Exclusion Tampered (critical) |
| End to end | Every 5 minutes (first after 30 s) a child `/bin/sh` creates and removes `/var/tmp/.siem-sensor-canary-<pid>`. If the sensor does not see it within 15 s, its programs were detached or its tracepoints stopped firing. Only changes are reported; the canary's own events are not shipped. | `event=sensor_blind`, then `event=sensor_recovered` | SIEM Agent Sensor Blind (high) |

The canary needs the file event group (not in `disabled_events`) and `/bin/sh`; without them it is not run, and nothing is reported. The child's process start is ordinary telemetry (parent `siem-agent`).

Integrity: the heartbeat's binary and config hashes report `unreadable` once a file could not be hashed on two checks in a row (5 minutes apart), so a deleted or locked binary or config raises *SIEM Agent Binary/Config Modified* instead of going quiet. One failure alone is ignored: an upgrade replacing the file can fail once.

## Configuration

```yaml
linux_sensor:
  disabled: false
  disabled_events: []   # any of: file, module, ptrace, privilege, memfd, exit, access
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
