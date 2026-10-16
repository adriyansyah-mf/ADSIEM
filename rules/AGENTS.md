# RULES & DECODERS (detection content — YAML data)

Both directories are **seeded into Postgres on worker startup** by `worker/worker/seeder.py`. Seeding is idempotent by `title` (rules) / `name` (decoders): rows for existing titles are never overwritten, so dashboard edits survive redeploys. Adding a file is the deployment mechanism — there is no build step.

Current counts: **70 rules**, **22 decoders** (treat counts as data; they change).

## RULES (`rules/*.yaml`)

Standard Sigma. Two field vocabularies — pick the right one for the logsource:

| Logsource | Field style | Examples |
|---|---|---|
| `process_creation` | **Sigma native** | `Image`, `CommandLine`, `ParentImage`, `User`, `ProcessId`, `ParentProcessId` |
| everything else | **ECS dotted** | `event.action`, `user.name`, `source.ip` |

- `process_creation` rules are fed by the Go agent's eBPF monitor (decoded by `decoders/linux_process_exec.yaml`) and use Sigma field names so public **SigmaHQ `process_creation` rules drop in unmodified**. No shipped rule currently exercises this path, so it is a contract to honour, not a pattern to copy from the existing 70 files.
- Non-`process_creation` rules must match the field names a decoder actually emits — an unmatched `selection` key means the rule silently never fires.
- Families present: linux auth/priv-esc, web (SQLi/XSS/SSRF/SSTI/deserialization/log4shell/spring4shell/shellshock), firewall (FortiGate), Windows (security/sysmon), persistence (cron/systemd/sudoers/SSH-key), mining/exfil/C2.

## DECODERS (`decoders/*.yaml`)

Two types, both map to dotted ECS-ish output fields:

**regex** (named capture groups → fields):
```yaml
name: my_decoder
log_type: linux_auth          # must match the agent's logs[].type
type: regex
priority: 50                  # lower = tried first
enabled: true
pattern: 'Failed password for (?P<user>\S+) from (?P<src_ip>\S+)'
fields:
  event.action: login_failed  # output_field: capture_group
  user.name: user
  source.ip: src_ip
```

**kv** (`key=value` / `key="quoted"` logs; what the eBPF process-exec path uses):
```yaml
name: my_kv_decoder
log_type: some_log_type
type: kv
priority: 10
fields:
  event.action: action        # output_field: kv_key
static_fields:
  event.category: network
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Seeding logic / idempotency key | `worker/worker/seeder.py` | per-title SAVEPOINT; safe across 2 replicas |
| Field names a rule can match | the decoder with the same `log_type` | rule selection keys must exist in decoded output |
| Dashboard rule/decoder editor | `dashboard/src/pages/RulesPage.tsx`, `DecodersPage.tsx` | YAML write → Test → Save |
| Server-side YAML validation | `server-api/app/api/routes/decoders.py` `_validate_decoder_yaml` | rejects non-`regex|kv`, regex without `pattern` |
| Decoder test endpoint | `POST /api/decoders/test` | imports `worker.decoder_engine` |

## CONVENTIONS

- **Filename** = snake_case describing the behaviour (`ssh_brute_force.yaml`, `kernel_module_suspicious.yaml`).
- **`log_type` in a decoder must exactly match** an agent `logs[].type` (`linux_auth`, `syslog`, `linux_process_exec`, `nginx_access`, `fortigate_traffic`, ...). A typo means zero decodes for that source.
- **Decoder `priority`** orders evaluation; put narrow/high-confidence decoders lower.
- **Rules are detection only** — response actions belong in SOAR playbooks (`worker/worker/soar_engine.py`), not rule YAML.

## ANTI-PATTERNS

- **Do not rename an existing rule `title`** to "update" it — seeding keys on `title`, so a rename creates a duplicate rule and leaves the old one active.
- **Do not mix field vocabularies** — using `Image` in an ECS-logsource rule (or `event.action` in a `process_creation` rule) makes it dead.
- **Do not put `CREATE TABLE`-style config into these files** — they are pure content, no logic.
- **Do not assume an edited DB row is permanent** — only *new* titles are seeded; edit YAML and bump the title, or edit in the dashboard and accept it lives only in the DB.
