# Compliance Manager — OS-Level Hardening Checks

Status: Approved
Date: 2026-09-08

## Context

The Compliance Manager (shipped earlier this session) evaluates each
enrolled endpoint against ISO 27001 / PCI-DSS / SOC 2 control references,
but its checks are shallow proxies computed server-side from data the agent
already happened to collect (hygiene score, open ports, disk usage, FIM
event counts, UID-0 duplicates). The user wants this closer to how
Bitdefender GravityZone's endpoint risk/compliance module works: real
CIS-Benchmark-style hardening checks executed **on the endpoint itself**,
since the backend has no way to inspect `/etc/ssh/sshd_config` or PAM
config remotely — only the agent has direct OS access.

## Scope

- **OS target**: Linux only for v1 (matches the current agent — RPM/DEB
  packaging, systemd, Rocky/Debian hosts). Design the check/report shape to
  be OS-agnostic so a future `windows.go` can implement the same interface
  without changing the schema or backend.
- **Categories (v1)**: account/password policy, network/firewall hardening,
  SSH hardening, kernel/filesystem hardening.
- Out of scope for this spec: remediation-guidance text, PDF export, and
  daily history/trend snapshots — approved in principle as follow-ups, to
  be layered on top of these deeper checks once they exist, not implemented
  in this pass.

## Architecture

New Go package `agent/internal/hardening/`:

- `types.go` — `Check{ID, Category, Title, Status, Detail}` where Status is
  one of `pass | fail | not_applicable | error`; `Report{Checks []Check}`.
  This shape carries no Linux-specific assumptions.
- `linux.go` — `Collect() (*Report, error)`, implementing all v1 checks by
  reading local files/commands (no root-only operations that would break
  the agent's existing non-privileged install path where avoidable; where a
  check genuinely needs a privileged read, it reports `error` with a clear
  detail rather than silently guessing).
- Future `windows.go` (`//go:build windows`) provides the same `Collect()`
  signature — not implemented now, just the reason `types.go` stays
  OS-agnostic.

### Checks catalog (v1, ~12-14 checks)

| ID | Category | What it checks |
|---|---|---|
| `acct-password-maxage` | account | `PASS_MAX_DAYS` set and ≤ 90 in `/etc/login.defs` |
| `acct-password-complexity` | account | PAM `pam_pwquality`/`pam_cracklib` configured |
| `acct-lockout` | account | PAM `faillock`/`tally2` configured for failed-login lockout |
| `acct-no-empty-password` | account | no entry in `/etc/shadow` with an empty password field |
| `acct-no-duplicate-root` | account | no non-root account with UID 0 (already exists as `local_account_hygiene`; migrates into this catalog) |
| `net-firewall-active` | network | firewalld/ufw/nftables/iptables service active with at least one deny/default-drop rule |
| `net-ip-forward-disabled` | network | `net.ipv4.ip_forward=0` unless host is a designated router |
| `net-no-legacy-services` | network | no FTP/Telnet/r-commands/X11 listening (already exists as `open_ports_hardening`; migrates into this catalog) |
| `ssh-no-root-login` | ssh | `PermitRootLogin no` in `sshd_config` |
| `ssh-no-password-auth` | ssh | `PasswordAuthentication no` (reported, not enforced — hosts using key-only auth already pass) |
| `ssh-protocol-2` | ssh | `Protocol 2` (or omitted, which defaults to 2 on modern OpenSSH — reported as pass either way) |
| `ssh-max-auth-tries` | ssh | `MaxAuthTries` ≤ 4 |
| `kernel-aslr-enabled` | kernel | `kernel.randomize_va_space=2` |
| `kernel-ptrace-restricted` | kernel | `kernel.yama.ptrace_scope` ≥ 1 |
| `kernel-coredump-restricted` | kernel | `fs.suid_dumpable=0` |
| `fs-tmp-noexec` | kernel | `/tmp`, if its own mount, has `noexec,nosuid` options |

Each check that reads a config file treats "file missing" as `not_applicable`
with an explanatory detail, never as `fail` — a missing PAM module file on a
minimal container image isn't necessarily a real gap on that host.

### Data flow

1. Agent's existing hygiene-collection cadence also calls
   `hardening.Collect()` and attaches the result to the same
   `HygieneSnapshot` report the agent already sends (`agent/internal/hygiene/types.go`'s `Report` gets a new
   `HardeningChecks []hardening.Check` field) — no new wire message, no new
   heartbeat cadence.
2. `server-api`: `HygieneSnapshot` model gets a new `hardening_checks JSONB`
   column (ad-hoc `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` migration,
   matching this codebase's existing migration pattern in `main.py`).
3. `server-api/app/services/compliance.py`: the existing
   `local_account_hygiene` and `open_ports_hardening` checks are rewritten
   to read the new `hardening_checks` array (matching by ID) instead of
   their old shallow heuristics; two new checks/controls are added per
   framework — `ssh_hardening` and `kernel_hardening` — each aggregating
   the relevant `hardening_checks` entries into one control status (`met`
   if all relevant checks pass, `partial` if some, `gap` if all fail,
   `not_automated` if no hardening data collected yet for this host).
4. Dashboard: no new UI surface needed — `ComplianceManagerPage.tsx`
   already renders whatever controls the API returns; the two new controls
   (SSH hardening, kernel hardening) just appear in the existing table.

### Error handling

- A check that cannot run on a given host (e.g. no `sysctl` binary, no PAM)
  returns `not_applicable`, never fabricates `pass`/`fail`.
- If the whole `hardening.Collect()` call fails (unexpected panic path,
  guarded by a `recover()`), the agent logs it and sends the hygiene report
  without `HardeningChecks` — matching this agent's established
  graceful-degradation pattern (a failed sub-collector never blocks the
  rest of the report).
- Backend: a `HygieneSnapshot` with no `hardening_checks` data (older agent
  version, or the above failure case) makes the two new controls report
  `not_automated`, and the two migrated controls (`local_account_hygiene`,
  `open_ports_hardening`) fall back to their current shallow logic so
  older, not-yet-upgraded agents don't regress to a worse compliance view.

### Testing

- Go unit tests for each `hardening` check function against fixture
  config files (`testdata/sshd_config.hardened`, `.unhardened`, etc.) —
  matching the existing `agent/internal/buffer/buffer_test.go` pattern.
- Rebuild the local dev stack, verify a real container/VM's hygiene
  snapshot now includes `hardening_checks`, and that `/compliance` shows
  the two new controls with real pass/fail data.
- Deploy to production the same way as the last agent update this
  session: rebuild `package-builder` with a version bump, `rpm -Uvh` on
  WAF-SERVER, verify the new fields appear via the API.

## Explicitly deferred (approved in principle, not this spec)

- Remediation-guidance text per check
- PDF export of a compliance report
- Daily history snapshots + trend sparkline (needs a new table + a worker
  scheduled loop)
