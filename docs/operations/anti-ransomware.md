# Anti-ransomware

Roadmap item 3.4. `agent/internal/ransomguard` stops ransomware two ways and reports every detection as a `ransomware_activity` line.

## Canary files

The agent plants `!siem-canary.pdf` (sorts before anything else) and `.siem-canary.docx` (hidden) in:

- Linux: `/root`, `/home/*`, `/srv`, `/var/www`
- Windows: `C:\Users\*\Documents`, `C:\Users\*\Desktop`, `C:\Users\Public\Documents`

Nothing legitimate touches them. On Linux the eBPF sensor (`internal/linsensor`) reports a write, rename or delete of a canary with the process that did it, and the guard acts at once (`detection=canary`). Every 30 seconds the agent also checks the canaries' content and recreates missing ones. A change found that way has no process attached (`detection=canary_changed`). This is the only canary signal on Windows and on Linux hosts without eBPF.

## Bulk-encryption heuristics (Linux)

Per process, over a one-minute window of file events:

| Detection | Fires when |
|---|---|
| `extension_change` | 20 or more renames to a new extension, at least 70% of them to the same one (`.locked`, `.enc`, a random suffix) |
| `mass_modify` | 200 or more files written across 10 or more directories, with 50 or more deletes or renames |

A heuristic hit is **confirmed** only if most of the newest files the process wrote (up to 3, first 4 KB each) have an entropy of at least 7.2 bits per byte, which is what encrypted data looks like. Unconfirmed hits are logged (`confirmed=false`) but raise no alert and kill nothing. Package managers, git, rsync, backup tools, container engines and build tools are excluded. Add your own with `allow_images`. Interpreters such as python and node are deliberately not excluded.

## Response

On a canary hit or a confirmed heuristic, the agent stops the process and its descendants (SIGSTOP, then SIGKILL) and reports `response=killed` with `Killed=<n>`. It never kills PID 1, itself, systemd, init or sshd (`response=kill_refused`). With `isolate: true` it also isolates the host through the firewall engine, which needs `firewall.enabled`. Windows only reports, because without per-process file events there is no process to stop.

Measured with the real sensor: a test encryptor was stopped after 20 of 400 files. On a busy desktop, 90 seconds of normal activity (2,107 file events) gave no detections, and a full `go build -a` gave one unconfirmed detection before build tools were allowlisted.

## Configuration

```yaml
ransomware:
  disabled: false
  report_only: false      # true: never kill, only report
  isolate: false          # true: also isolate the host on a confirmed detection
  canary_dirs: []         # globs; replace the defaults
  canary_names: []
  allow_images: []        # extra basenames the heuristics ignore
```

## Alerts

`decoders/ransomware_activity.yaml`. Two rules: *Ransomware Activity On Endpoint* (critical, `ransomware.confirmed: true`, which covers canary hits and confirmed heuristics) and *Ransomware Canary File Changed* (high, the periodic check).

## Testing

`guard_test.go` covers the thresholds, allowlist, window, entropy confirmation, canaries and responses with a fake kill. With root and BTF, `TestRansomwareEndToEnd` runs a child process that encrypts and renames files, then one that writes a canary, and requires both to be killed (CI runs it under sudo). `RANSOM_FP=10m -test.run TestFalsePositives` watches the host with kill off and prints any detection.
