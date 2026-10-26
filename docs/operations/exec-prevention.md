# Execution prevention (Linux)

Roadmap item 3.3. Linux agents check every program before it starts against the rules on the dashboard's **Prevention** page (`/api/prevention-rules`) and either report the match (**detect**) or refuse to run it (**block**, the exec fails with `EPERM`). New rules default to detect. Review the alerts first, then switch the rule to block; per-group policy (roadmap 2.4) will make that per group.

## Rules

| Type | Value | Matches |
|---|---|---|
| Directory | `/dev/shm` | any program or script below that directory (sub-directories too, across mounts) |
| Executable path | `/opt/x/bin/tool` | exactly that file |
| Parent → child | parent `nginx, apache2, php-fpm8.2`, child `sh, dash, bash` | a process whose executable is one of the parents starting one of the children (web shell, document → shell) |
| SHA-256 | 64 hex characters | a file with that content, wherever it is |

Names in parent rules are executable basenames as the kernel sees them, after symlinks are resolved: list `dash` next to `sh` on Debian and Ubuntu. Scripts are checked as themselves and then as their interpreter.

The agent **never blocks** itself, init, systemd, `sh`/`bash`/`dash`, `sshd`, `sudo`, `login`, `nft` or `iptables`. A block rule that would cover one of them (a path or hash rule, or a directory such as `/usr` or `/`) is kept as detect and the agent logs why.

## Engines

- **BPF LSM** (`lsm/bprm_check_security`, `agent/internal/prevent/bpf/prevent.bpf.c`) decides directory, path and parent rules in the kernel. It needs `bpf` in `/sys/kernel/security/lsm`. Many distributions build it but leave it out of the boot list; add it with `lsm=...,bpf` (keep the existing entries, see `cat /sys/kernel/security/lsm`).
- **fanotify** (`FAN_OPEN_EXEC_PERM`) decides hash rules, and all rules on kernels without BPF LSM. It runs in a **separate helper process** (the agent binary started with `SIEM_AGENT_FANOTIFY_HELPER=1`), never inside the agent. The agent forks commands with vfork, and a responder in the same process can deadlock every exec on the host behind its own garbage collector. The helper fails open: a full queue is answered "allow", files over 64 MB are not hashed, and when the agent stops the helper exits and the kernel allows whatever is pending. It only runs while a rule needs it.

The agent fetches rules every minute (`POST /api/ingest/prevention-rules`, answered "unchanged" while the set is the same) and re-resolves directory rules, so a directory created later is covered within a minute.

## Alerts

Every match is a `linux_exec_prevention` line (`decoders/linux_exec_prevention.yaml`): `action=blocked|detected`, `rule`, `rule_type`, `engine`, `Image`, `ParentImage` (a basename from the LSM engine), `SHA256` (fanotify). The same rule, program and parent are reported at most once a minute. Rules `linux_exec_blocked.yaml` (high) and `linux_exec_detected.yaml` (medium) raise the alerts.

Agent config: `prevention.disabled: true` stops enforcing and reporting on that host.

## Testing

`internal/prevent/rules_test.go` covers validation, the guard and matching. The end-to-end tests load both engines into the running kernel, block and allow real executions, and use only files they create (both engines act host-wide). CI runs them under `sudo`; the LSM half skips on a runner kernel without BPF LSM. Locally:

```sh
cd agent && make bpf
CGO_ENABLED=0 go test -c -o /tmp/prevent.test ./internal/prevent/
docker run --rm --privileged --pid=host -e PREVENT_E2E=1 -v /tmp/prevent.test:/t:ro debian:bookworm-slim \
  sh -c 'mount -t tracefs nodev /sys/kernel/tracing; mount -t securityfs none /sys/kernel/security; /t -test.v'
```
