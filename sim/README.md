# Attack Simulator (dev only)

Continuously generates attack traffic and pushes it through the real ingest
path, so the whole pipeline — decode → Sigma → alert → SOAR → dashboard —
exercises itself without a real attacker.

## How it works

Every cycle:

1. The LLM is asked to invent a **scenario**: name, description, MITRE
   technique, target log source, and the raw log lines that express it.
2. The proposal is **validated against the real decoder regex** for its log
   type. Lines that would not parse are dropped; a scenario with no usable
   lines is rejected outright.
3. The lines are POSTed to `/api/ingest/log` with an agent token, exactly as
   `siem-agent` would.
4. Sleep, repeat.

If the model is unavailable or returns something unusable, a deterministic
catalogue in `scenarios.py` is used instead, so the loop never stalls.

## Why log types matter

The log type determines which decoder runs, and therefore which rules can fire.
Sending `sudo` lines as `syslog` decodes them to a generic `syslog_message` and
triggers nothing — sudo escalation only fires when sent as `linux_auth`.

Validation reads the **real decoder YAML files** rather than a hardcoded
pattern, so every decoder for a log type is honoured. `linux_auth` alone has
seven (failed login, sudo, su, useradd, cron, pam session, ssh accepted); an
earlier version modelled only the failed-login regex and silently rejected every
sudo and useradd scenario as unparseable.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SIM_AGENT_TOKEN` | — | agent token used for ingest (required) |
| `SIM_AGENT_ID` | — | agent UUID the logs are attributed to (required) |
| `SIM_HOSTNAME` | `agent-demo` | hostname recorded on events |
| `SIM_INTERVAL_SECONDS` | `20` | base delay between cycles |
| `SIM_JITTER_SECONDS` | `8` | random extra delay added |
| `SIM_LLM_ENABLED` | `true` | set `false` for catalogue-only |
| `SIM_SCENARIOS` | — | comma-separated catalogue keys to restrict to |
| `SIM_ATTACKER_NET` | `203.0.113.` | attacker IP prefix (RFC 5737 TEST-NET-3) |
| `NINEROUTER_BASE_URL` | `http://9router:20128/v1` | LLM endpoint |
| `NINEROUTER_API_KEY` | — | LLM key; without it the catalogue is used |
| `NINEROUTER_MODEL` | `combo` | model name |

## Running

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build attack-sim
docker compose -f docker-compose.yml -f docker-compose.dev.yml logs -f attack-sim
```

Watch alerts appear:

```bash
docker compose exec -T postgres psql -U soc -d soc_platform \
  -c "SELECT title, severity, source_ip, created_at FROM alerts ORDER BY created_at DESC LIMIT 10;"
```

## Scope

This is a **lab tool**. It only ever posts read-path log events through an
agent-authenticated endpoint; it cannot change rules, users, or settings. Keep
it out of production compose files.
