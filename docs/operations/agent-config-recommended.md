# Recommended agent configuration

What to set on every agent, and on the server's group policy, for agent 1.27.3
and later. The packaged templates (`agent/packaging/config.yaml`,
`agent/packaging/windows/config.yaml`) already hold most of it; this page says
what to change for each kind of host and why.

Two places hold settings:

- **`config.yaml` on the host** (`/etc/siem-agent/config.yaml`,
  `%ProgramData%\SIEMAgent\config.yaml`): what the agent collects and its local
  safety switches. A change needs an agent restart.
- **Group policy on the server** (Policies page, `server-api/app/services/agent_policy.py`):
  which protections act and how hard. Agents pick changes up within a heartbeat.

## 1. Every agent

```yaml
config_version: 2

agent:
  group: <group>            # one group per environment or team; policies and
                            # baselines (UEBA, behaviour, lateral) are per group
  buffer_size: 10000

server:
  url: https://siem.example.com   # HTTPS; see "Trusting a self-signed certificate"
  heartbeat_interval: 30

firewall:
  enabled: true             # containment (isolate, block IP, IP IoC blocklist)
  backend: auto
  dry_run: false
  protected_ips:            # never blocked, even by isolation: your admin
    - 10.0.0.0/24           # jump host / VPN range (the SIEM server is
                            # protected already)
```

Leave these at their defaults unless a host proves they hurt it: `yara`,
`memory_sweep`, `ransomware`, `prevention`, `project_scan`, `update`,
`linux_sensor` / `etw`. All of them are on by default.

### Log sources: one source per file

Each file must appear **once**. A glob that overlaps a named path ships every
line twice, and as two log types. On otakunesia, `/var/log/*.log` re-sent
`auth.log` as `syslog`, which doubled alerts and broke the SSH lateral-movement
edges. Prefer named paths with their own `type`, and check the Agents page →
Log sources for duplicates after enrolling.

## 2. Linux

The packaged template plus what the host runs:

```yaml
netwatch:
  enabled: true             # connect/accept/bind/DNS: feeds IP IoC matching,
  snapshot_fallback: true   # beaconing, UEBA host features and the lateral graph

logs:
  # Debian/Ubuntu (rsyslog). RHEL: /var/log/secure (linux_auth), /var/log/messages (syslog)
  - path: /var/log/auth.log
    type: linux_auth
  - path: /var/log/syslog
    type: syslog
  - path: /var/log/audit/audit.log      # if auditd runs
    type: linux_audit
```

| Host runs | Add |
|---|---|
| Apache | `/var/log/apache2/access.log` → `apache_access`, `/var/log/apache2/error.log` → `apache_error` (RHEL: `/var/log/httpd/…`) |
| Nginx | `/var/log/nginx/access.log` → `nginx_access`, `/var/log/nginx/error.log` → `nginx_error` |
| PHP-FPM | the pool's `error_log` → `php_error` |
| MySQL / MariaDB | general log, if enabled → `mysql_general` |
| Postfix | `/var/log/mail.log` → `postfix` |
| iptables/ufw logging | kernel log lines are in `syslog` already; use `linux_iptables` only for a dedicated file |

**Web servers.** Web attacks (SQLi, command injection, webshells) are detected
from the access log, so a web server without its access log is half blind: on
otakunesia the DVWA command injection showed up as a process tree only. Apache
and many services run with systemd **PrivateTmp**. Agent 1.27.3 reports the
host path (`HostImage`, `HostTargetFilename`) and quarantines the right file, so
older agents on web servers should be updated first.

## 3. Windows

The packaged template is the recommendation: Security, System, Application,
Sysmon, PowerShell/Operational and CodeIntegrity/Operational. In addition:

- **Sysmon**: install it with a maintained config. The ETW sensor (`etw.mode:
  auto`) steps aside when Sysmon is present, so nothing is reported twice.
- **PowerShell script block logging** (GPO: *Turn on PowerShell Script Block
  Logging*): without it the PowerShell/Operational channel stays empty.
- **Audit policy**: enable logon (4624/4625, logon types feed the lateral
  graph), process creation, and account management auditing.
- `anti_tamper.unlock_service` stays commented out.

## 4. Group policy (server side)

| Setting | Recommended | Why |
|---|---|---|
| `malware_action` (Known-malware hashes) | `block` | kill at start and quarantine; hashes come from MalwareBazaar and from YARA hits on any host |
| `ml_action` (Static ML) | `block` on servers, `detect` on developer workstations | block quarantines and stops the running program; developers build and run unsigned binaries |
| `ip_ioc` | `block` (default) | drops traffic to and from listed IPs/CIDRs |
| `ioa` | `detect` (default) | |
| `script_scan` | `detect`, then `block` once a week of alerts is clean | |
| `ransomware_mode` | `stop` (default) | isolate on ransomware: on for servers you can reach out of band |
| `app_control` (Windows) | `audit` for a week, then `enforce` | check `App Control Would Block A Program (Audit)` alerts before enforcing |

Exclusions belong in the policy (path, program, SHA-256 or command line, per
scope), not in disabled sensors.

## 5. Durable evidence (when to turn it on)

`evidence.enabled` keeps every event in an on-disk journal until the server
confirms receipt, so nothing is lost across crashes, reboots or long outages.
The release gate has passed on both OSes (`agent-evidence-validation.md`), but
**the order matters**: an agent with evidence on, against a server that does
not advertise it, holds **all** of its events (status `Blocked
(protocol_unsupported)`). There is no fallback to the legacy path.

1. **Server first** (on the SIEM host, as root). `docker-compose.yml` passes
   `EVIDENCE_INGEST_ENABLED` and `EVIDENCE_GROUP_BUDGET_BYTES` from `.env` to
   server-api; before that change the variable never reached the container.
   ```bash
   cd /opt/ADSIEM && git pull
   grep -q '^EVIDENCE_INGEST_ENABLED=' .env \
     && sed -i 's/^EVIDENCE_INGEST_ENABLED=.*/EVIDENCE_INGEST_ENABLED=true/' .env \
     || echo 'EVIDENCE_INGEST_ENABLED=true' >> .env
   docker compose up -d server-api
   docker compose exec server-api python -c \
     "import httpx; print(httpx.get('http://localhost:8000/ready').text)"
   # must print "evidence":"ready"
   ```
   A 503 means the database is not durable (`fsync`, `full_page_writes`) or
   the evidence tables are missing: fix that first.
2. **Then a few agents** (both OSes, one group):
   ```yaml
   evidence:
     enabled: true
     dir: evidence            # inside agent.state_dir
     max_bytes: 1073741824    # 1 GiB local budget; never evicts unconfirmed events
   ```
   Restart the agent. Within a minute the Agents page → Evidence delivery
   shows `Healthy`.
3. Review for a day (`agent-evidence-recovery.md`, Rollout order step 4), then
   10% of agents, then the fleet.

Until step 1 is done, keep `evidence.enabled: false`. The Evidence delivery
column then reads "not reported", which is expected.

## 6. Check after a change

- Agents page: online, expected version, Evidence delivery as planned.
- Log search for the agent over the last 5 minutes: each log type you
  configured shows up once, not twice.
- `journalctl -u siem-agent -n 50` (Linux) or the Application event log
  (Windows): no `blocked`, `failed` or `permission denied` lines.
