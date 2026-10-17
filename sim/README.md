# Lab: agent-demo VM + real attacker (dev only)

`agent-demo` **is** the demo VM: it runs the SIEM agent and a deliberately
vulnerable company-profile app on the same host, so the agent tails its own
machine exactly like a real endpoint would.

```
attacker --HTTP/SSH--> agent-demo:1337 / :22
                        |- Apache + PHP-FPM + MySQL -> /var/log/apache2/*, /var/log/syslog
                        |- sshd                      -> /var/log/auth.log
                        +- /app/agent                -> tails those files -> server-api
```

No component fabricates log lines and nothing talks to `/api/ingest/log`
except the agent itself.

## Why the old simulator is gone

An earlier version POSTed LLM-generated log lines straight to
`/api/ingest/log`. It proved the pipeline worked but never exercised collection:
a broken tailer, a bad mount, an Apache logging misconfiguration or a decoder
mismatch all went unnoticed. Now, if the attack does not log, the SIEM stays
empty — which is the signal a lab should give you.

## The demo app

| Path | Vuln |
|---|---|
| `/` | company profile index |
| `/staff.php?id=` | concatenated SQL — UNION / SLEEP / BENCHMARK reach MySQL |
| `/gallery.php?page=` | `include()` with no allow-list — LFI |
| `/login.php` | weak credential form, 401 on failure |

Accounts in `company_profile.staff`: `admin/admin123`, `editor/editor123`.
The box also runs sshd with `root:toor-lAB-demo` and `demo:demo-lAB-pass`.

## Attacker techniques

| Technique | Target | Victim log |
|---|---|---|
| `web_scan` | `:1337` with `sqlmap` UA | 404/403 in `access.log` |
| `web_bruteforce` | `POST /login.php` | 401 trail |
| `sqli_union`, `sqli_timeblind` | `/staff.php?id=` | request + PHP/MySQL error |
| `lfi` | `/gallery.php?page=` | 200/404 |
| `cmd_injection` | `/contact.php?q=` | request |
| `bad_requests` | raw `nc` HTTP | Apache `error.log` |
| `ssh_invalid_user`, `ssh_bruteforce` | `:22` | `auth.log` failed-password burst |
| `port_scan` | `:22` | network telemetry only |

## Running

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build agent-demo attacker

# browse the target app
#   http://localhost:1337/
#   http://localhost:1337/staff.php?id=1
#   ssh -p 2222 demo@localhost

# watch the attacker
docker compose -f docker-compose.yml -f docker-compose.dev.yml logs -f attacker

# watch the logs the agent is tailing
docker exec siem-platform-agent-demo-1 tail -f /var/log/apache2/access.log
docker exec siem-platform-agent-demo-1 tail -f /var/log/auth.log
```

Fire one technique by hand:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm \
  -e RUN_ONCE=1 -e ATTACK_TECHNIQUES="sqli_union" attacker
```

## Tuning

| Variable | Default | Purpose |
|---|---|---|
| `ATTACK_INTERVAL` | `45` | seconds between techniques |
| `ATTACK_JITTER` | `20` | random extra seconds |
| `ATTACK_TECHNIQUES` | all | space-separated subset |
| `RUN_ONCE` | `0` | `1` = one technique, then exit |

## Verifying telemetry is real

```bash
# daemons must be writing real files, not /dev/stdout symlinks
docker exec siem-platform-agent-demo-1 ls -l /var/log/apache2/access.log /var/log/auth.log

# agent must be shipping events off its own box
docker compose logs --tail 5 agent-demo | grep 'buffer stats'

# alerts must carry the attacker's container IP
docker compose exec -T postgres psql -U soc -d soc_platform \
  -c "SELECT title, severity, source_ip, created_at FROM alerts ORDER BY created_at DESC LIMIT 10;"
```

## Scope

Lab only. Weak credentials and intentionally vulnerable PHP. Never expose
`:1337` or `:2222` beyond localhost and never deploy this image outside the lab.
