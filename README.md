# ADSIEM

**An AI-native SIEM + EDR + SOAR platform you run on your own servers.** A Go agent on
each Linux and Windows endpoint collects telemetry and stops threats on the host. A Python
detection pipeline decodes, correlates and scores every event. An AI analyst triages every
alert, groups alerts into cases and investigates them. Analysts approve the response in one
React dashboard, without Splunk/QRadar-scale infrastructure or licensing.

| | |
|---|---|
| Endpoint agent | Go, Linux (eBPF) + Windows (ETW), current release **agent-v1.27.3**, signed self-update |
| Detection content | **218** Sigma rules, **135** decoders, 7 built-in + 14 community YARA sets, SigmaHQ importer |
| Behaviour analytics | Host baselines (rare parent → child, rare new executables, beaconing), UEBA for users, IPs, hosts and processes, entity risk scoring, lateral movement graph |
| Ingest | Agent (HTTPS), agentless syslog UDP/TCP 514 (RFC 3164, RFC 5424, CEF), Suricata EVE, Zeek, FortiGate |
| AI | Auto-triage of every alert, AI case correlation, autonomous case investigator, SOC assistant, RAG over your SOPs |
| Response | Visual SOAR editor (15 node types, approval gates), isolate / kill / quarantine / block, live response |
| Storage | PostgreSQL 16 (pgvector) · Elasticsearch 8 · Redis 7 |

> **Ringkasan (Bahasa Indonesia).** ADSIEM adalah platform SIEM + EDR + SOAR berbasis AI
> yang berjalan on-premise. Agen Go di endpoint Linux dan Windows mengumpulkan telemetri dan
> mencegah ancaman langsung di host: RansomGuard, rantai IOA, isolasi host, karantina (yang
> juga menghentikan program yang sedang berjalan), YARA, blokir IP IoC, Windows App Control,
> dan web protection. Server mempelajari perilaku normal tiap host (proses induk-anak yang
> langka, program baru di folder temp, beaconing), menghitung skor risiko per host dan user,
> serta memetakan lateral movement antar host. Setiap alert ditriase AI, alert digabung menjadi kasus per kampanye
> penyerang, dan respons berdampak besar menunggu persetujuan analis lewat playbook SOAR
> visual. Log jaringan masuk tanpa agen lewat syslog/CEF, termasuk Suricata dan Zeek. Trafik
> OT (Modbus/DNP3) bisa dipantau dengan meneruskan `eve.json` Suricata ke halaman
> **Syslog devices**. Laporan AI dapat ditulis dalam Bahasa Indonesia.

> **Security Warning:** Default credentials (`admin` / `admin123`) are for development only.
> Change `JWT_SECRET`, `POSTGRES_PASSWORD`, `AGENT_ENROLLMENT_TOKEN`, and the admin password
> immediately in production. See [Production Deployment](#production-deployment).

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements) · [Services](#services) · [Server Installation](#server-installation)
- [Agent Installation](#agent-installation) · [RBAC](#rbac)
- [Adding Rules](#adding-rules) · [Adding Decoders](#adding-decoders) · [Syslog, Suricata, Zeek and OT](#syslog-suricata-zeek-and-ot)
- [Production Deployment](#production-deployment) · [Observability](#observability) · [Troubleshooting](#troubleshooting)
- [Documentation](#documentation) · [Testing and CI](#testing-and-ci) · [Roadmap](#roadmap)

## Features

### Endpoint agent (Linux and Windows)

One static Go binary per host (`agent/`). It enrolls with a one-time token, then heartbeats
every 30 s to pick up config, log sources, FIM paths, policies and tasks. Undelivered data
spills to disk and replays after an outage. A durable evidence journal keeps detections
across crashes and reboots (`-evidence-list`, `-evidence-salvage`, …).

| Capability | Linux | Windows | Where |
|---|---|---|---|
| Process, file, network, DNS telemetry | eBPF (exec, file write/rename/delete, kernel modules, ptrace, privilege gain, memfd exec, connect/accept/bind; network watch on by default). A process in another mount namespace (systemd PrivateTmp, containers) also reports the host path (`HostImage`, `HostTargetFilename`) | ETW (process, file, registry persistence, image load, network, DNS, AMSI) | `internal/procexec`, `linsensor`, `netwatch`, `mountns`, `etw`, `winsensor` |
| Sensor health self-report (sensor stopped, silent, events lost) | ✓ | ✓ incl. ETW lost events | `internal/sensorstat` |
| Log collection | File and glob tailing with rotation | Files + Event Log channels (`eventlog:<channel>`), Sysmon | `internal/tailer`, `winevent` |
| IOA behaviour chains | ✓ | ✓ | `internal/ioa` (agent 1.23+) |
| **RansomGuard** anti-ransomware | ✓ canary files, precursor rules, entropy and mass-modify heuristics, kill process tree or isolate | ✓ | `internal/ransomguard` |
| Static ML (PE + ELF; an ELF in `/tmp`, `/var/tmp` or `/dev/shm` is held to stricter thresholds) | ✓ | ✓ | `internal/mlscore`, `mlscan` |
| YARA (pure Go, on-access, full-disk, memory) | ✓ | ✓ | `internal/yara`, `yarascan`, `fullscan`, `memscan` |
| Script, archive and document scanning | ✓ | ✓ | `internal/scriptscan`, `unpack` |
| Malware hash + TLSH matching | ✓ | ✓ | `internal/malhash`, `tlsh` |
| Credential-store access watch | ✓ fanotify | — | `internal/credwatch` |
| Developer/project compromise scan | ✓ | ✓ | `internal/projscan` |
| File Integrity Monitoring | ✓ SHA-256, debounced | ✓ | `internal/fim` |
| Execution prevention | Pre-exec (BPF LSM + fanotify) | Post-exec terminate on block rules, plus **App Control (WDAC)** in `audit` or `enforce` to block before start | `internal/prevent`, `appcontrol` |
| Host isolation, block IP, firewall rules | nftables (anti-lockout guard, expiry) | netsh | `internal/firewall` |
| IP IoC blocklist (drop or report traffic to and from listed IPs/CIDRs) | nftables `inet siem_ioc` | WFP dynamic session, netsh fallback | `internal/ipblock`, `firewall` |
| Quarantine / restore, kill process | ✓ stops the programs running the file (by inode, also inside PrivateTmp and containers) | ✓ protected DACL store, stops running programs | `internal/task` |
| Web protection (domain block page, local CA) | ✓ | ✓ | `internal/webblock` |
| Live response | ps, netstat, users, glob, hash, read file, persistence, dmesg, open files, YARA, memory YARA/RWX, exec | ps, netstat, users, services, programs, Event Log, YARA, memory scan | `internal/task` |
| Hygiene inventory | OS, patches, ports, disk, packages (CVE matching) | OS, ports, disk, programs | `internal/hygiene` |
| User pop-up notifications | ✓ | ✓ | `internal/notify` |
| Local threshold detections | ✓ | ✓ | `internal/detect` |
| Group protection policy (which protections run, exclusions) | ✓ | ✓ same policy | `internal/policy` |
| Offline enforcement (last prevention + YARA rule set cached, tamper-evident) | ✓ | ✓ | `internal/rulecache` |
| Encrypted sample archives (ZipCrypto, `infected`) scanned in memory | ✓ | ✓ | `internal/zipcrypto` |
| Own-process tracking (spoofed parent PID can't pass as the agent) | ✓ | ✓ | `internal/ownproc` |
| Durable evidence journal | ✓ | ✓ | `internal/evidence` |
| Disk-backed send buffer, replay after outage | ✓ | ✓ | `internal/buffer` |
| Signed self-update | systemd-run, Ed25519 manifest | MSI, Ed25519 manifest | `internal/update` |
| Packaging | `.deb`, `.rpm` | `.msi`, `.zip` | `agent/packaging` |

**Self-protection.** Uninstall needs an uninstall token (`-verify-uninstall`). Heartbeats
check the token hash, and the `agent_integrity` task verifies the binary. Tampering raises
`siem_agent_*` alerts (`docs/operations/agent-tamper.md`). On Windows the agent runs as a
service (`-install` / `-uninstall`).

**Agent tooling** (`agent/cmd/`):
- `siem-update-sign` creates and checks the update signatures agents require.
- `yaracheck` validates YARA rules on the server with the same engine the agents use.
- `yarapack` builds the community YARA pack from YARA-Forge.
- `detbench` benchmarks file detection on malware and known-good samples.
- `winevent-fmt` feeds the SigmaHQ replay harness.

### Ingest and integrations

- **Agent ingest:** `POST /api/ingest/v2/logs` (batched, `X-Agent-Token`) into a Redis stream.
- **Agentless syslog:** a separate `syslog-receiver` listens on UDP/TCP 514 and accepts RFC
  3164, RFC 5424 and CEF. Only registered senders are accepted, and each sender's address
  maps to a log type (**Environment → Syslog devices**). Unknown senders appear with a sample
  message so you can register them.
- **Network sensors:** decoders for Suricata EVE (alert, DNS, HTTP, TLS, every other
  `event_type`) and Zeek JSON (conn, DNS, HTTP, SSL, notice), plus rules on Suricata severity
  and Zeek notices.
- **OT networks:** send Suricata's `eve.json` with Modbus/DNP3 app-layer parsing enabled, from
  a sensor on a mirror port. Those records arrive with `network.protocol: modbus`/`dnp3`. See
  [Syslog, Suricata, Zeek and OT](#syslog-suricata-zeek-and-ot).
- **Firewalls and appliances:** FortiGate (traffic, UTM, event, VPN, admin login) and any CEF
  sender.
- **135 decoders** in four types (`regex`, `kv`, `json`, `cef`), covering Linux auth, syslog,
  auditd, iptables, Windows Security/System/PowerShell/Sysmon/ETW, Apache, Nginx, PHP,
  MySQL, Postfix and every agent-native detection.

### Detection

- **Sigma engine** (`worker/worker/sigma_engine.py`): field modifiers (`contains`,
  `startswith`, `endswith`, `re`, `base64`, `base64offset`, `wide`/`utf16`, `windash`,
  numeric compare), keywords, boolean conditions, threshold and correlation windows,
  `after:` sequences, and per-entity suppression.
- **218 bundled rules:** Linux, Windows, IOA chains, web attacks (SQLi, XSS, SSRF, LFI, RCE,
  Log4Shell, XXE, GraphQL, WordPress), network/firewall, Suricata/Zeek, ransomware, ML,
  YARA, credential access, kernel-thread masquerading (a `[kworker/…]`-named process that
  connects out or is exec'd), App Control, and agent tampering.
- **SigmaHQ import:** import the official releases (Core through All) and keep them updated.
  Your edits are preserved. Replaying SigmaHQ's regression samples loads all 3,768 rules.
- **UEBA:** Isolation Forest models for users, IPs, hosts and processes, retrained hourly, with
  baselines per group, per-feature explanations and a cold-entity guard. Placeholder users
  such as auditd's `(invalid user)` are ignored.
- **Host behaviour baselines** (`worker/worker/behavior.py`, server side): a rare parent →
  child process, a new rare executable from a user-writable folder, and periodic beaconing to
  an external host. First-seen findings start after `behavior_learning_hours` (default 72),
  and what several hosts of the group do counts as normal.
- **Entity risk** (`/entity-risk`): every alert adds risk to its host and user (by severity,
  plus a bonus per new MITRE tactic, halving every 24 h). An entity over
  `entity_risk_alert_threshold` (default 70) with two or more tactics raises one `[Risk]` alert.
- **Lateral movement graph** (`/lateral`): who reaches which host, how (SSH, RDP, SMB, WinRM,
  RPC, network logon) and as whom, built from SSH logins, Windows 4624 and agent connections.
  New paths, one host fanning out to many, and `A → B → C` chains raise alerts.
- **Threat intelligence:** VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, Shodan, URLhaus,
  WHOIS and GeoIP, run in parallel. A MalwareBazaar hash feed syncs into **Malware hashes**.
- **Agent health:** silent agents, sensor failures (a sensor stopped, went silent or lost
  events), and agents that still heartbeat but have shipped no logs for a set time
  (**Agent Log Silence Alert**) raise alerts.
- **MITRE ATT&CK** tags on every alert, with a coverage heatmap.

### AI SOC layer

All LLM calls go through `9router`, an OpenAI-compatible router with a fallback model chain
and usage accounting (`worker/worker/llm_gateway.py`). Point its providers at a local Ollama
model to keep inference on-prem.

- **AI L1 triage of every alert:** a triage graph enriches the alert with TI, UEBA context and
  RAG over past alerts and your SOPs. It then gives a verdict, escalates severity, opens or
  joins a case, starts auto-hunts and, from TI verdicts, web auto-blocks. Rate-limited calls
  go to a backoff retry queue (`ai_retry.py`).
- **AI case correlation:** the LLM picks the right existing case from validated candidates.
  Each alert-to-case link keeps its evidence (`case_correlation.py`).
- **Autonomous investigator** (**Investigate with AI** on a case): reads the case, searches
  logs and runs live-response artifacts on affected hosts. It writes new `AI.*` artifacts when
  none fits, then files a report with summary, evidence, IOCs, timeline, recommendations and
  verdict. Containment (isolate, kill, quarantine, block) stays with the operator. With
  **AI Investigation Commands** set to `approval`, the investigator may also ask to run a program
  on a host. Someone with `agents:manage` approves each command on the case before it runs.
  An allowlist (**AI Commands Without Approval**, e.g. `whoami,hostname`) skips the prompt,
  but shells, interpreters and credential paths always need approval. Runs have a budget and
  are scoped to the case's group. Steps are recorded in an investigation
  ledger with hypotheses, decisions and pinned evidence, and the investigation has its own
  chat.
- **SOC assistant:** a chat widget on every page that looks up alerts, cases, agents, UEBA,
  FIM, rules, logs and MITRE coverage. It is read-only and cannot touch settings, users or
  webhooks.
- **Knowledge and SOPs:** upload SOP documents and write knowledge articles. Both are embedded
  for retrieval, and PayloadsAllTheThings syncs weekly. The embedding model ships in the
  image, so retrieval works offline.
- **Reports:** executive reports and PDF export with a language selector, including Bahasa
  Indonesia. A weekly email digest can include an AI narrative.
- **YARA drafting:** the investigator proposes YARA rules from malware candidates
  (`yara_ai_generation`: `off`, `draft_only` or `full`).
- **On the case page:** AI L1 triage report, AI web research, AI campaign analysis, a
  narrative with MITRE techniques and recommended actions, and an attack timeline.
- **Learning from analysts:** **Correct** / **Incorrect** feedback on AI verdicts feeds the
  knowledge base (**Knowledge → Learned from feedback**). Later triage retrieves it.
- **Tuning:** a minimum alert severity for AI triage (lower alerts land as *Below threshold*
  and stay out of the New queue), a confidence threshold for opening or escalating cases, and
  separate model choices for triage and **Investigate with AI**.
- **Research:** `9router` web search through SearXNG, Tavily or a multi-provider search combo.

### Cases

- A case is one attacker's **campaign**, keyed by the IOCs it uses: public source IPs, file
  hashes, and for outbound behaviour (C2, exfiltration, download-and-run) the IP, domain or URL
  contacted. Alerts sharing an IOC join the same case on whichever host they fire, and the case
  lists the affected hosts. Hosts and usernames are never keys, so two attackers on one server
  are two linked cases.
- An alert without IOCs (local privilege escalation, persistence, …) joins the campaign already
  on its host. Cases that turn out to share an IOC are merged. A case an analyst is working on
  is linked instead of merged.
- The case keeps its furthest kill-chain stage. Post-compromise activity after brute force or
  initial access raises it to critical. Own public IPs, proxies and shared SaaS go in
  `case_ioc_exclusions`. Public DNS resolvers and big update/CDN domains are excluded already.
- Failed-only brute force from public IPs goes into one digest case per day
  (`bruteforce_digest_enabled`).
- Cross-host spread is detected and noted on the case.
- Each case has ownership, assignment, L2 escalation, review, a timeline, notes, linked
  evidence, remediations, an attack graph and analyst feedback.

### Response and SOAR

- **Visual playbook editor** (`/soar`): playbooks run when an alert or case event fires. Every
  run keeps each node's input, output and errors.
- **15 node types:** trigger, alert event, log search, scan, hunt, block IOC, if, TI enrich,
  AI decide (yes/no with confidence), **approval** (pauses the run with a timeout until an
  analyst decides), response (isolate, kill, scan, block IP), case, case evidence, case block
  IPs, notify (Slack, Teams, generic), and HTTP request. HTTP requests are SSRF-checked, accept
  curl import, and pass the response to later nodes as `{{ steps.<node>.body... }}`.
- **Live response console:** ad-hoc process lists, netstat, file pulls, YARA and memory scans,
  persistence checks, saved artifacts and fleet-wide hunts.
- **Web protection** (tabs: Blocklist, Allowlist, Block page, Feeds, Agents): domain block and
  allow lists per group, URLhaus and PhishTank feeds, auto-block from TI verdicts, a custom block
  page with preview, and per-agent status.
- **IP Blocklist** (`/ip-blocklist`, `/api/ip-blocks`): addresses or CIDRs per group with a
  reason and an optional expiry, also fed by `/api/ingest/ip-blocklist`. The group policy's
  `ip_ioc` mode decides whether agents drop the traffic (`block`) or only report it (`detect`).
  SOAR's **Block IOC** node can add an IP (`ip_block`) or a domain (`web_block`). Automation
  refuses private ranges and anything broader than /16.
- **Prevention rules:** execution prevention in detect or block mode. On Windows, **App
  Control** (Policies: `off` / `audit` / `enforce`) turns the block rules into a WDAC policy.
- **Quarantine** (automatic or from the dashboard) also stops the programs running the file.
  A path reported from inside a PrivateTmp or container is resolved to the file on the host.
- **Known malware hashes:** the agent action is `off`, `detect` (critical alert) or `block`
  (kill at start and quarantine the dropped file). Blocking can be limited to some groups.
  The MalwareBazaar feed adds new samples every 30 minutes and has its own retention. A file
  that matches a critical YARA rule on one host becomes a known-malware hash for every agent.
  Analysts can add hashes or mark one *Not malware*.
- **YARA rules:** seed the built-ins, write rules, and run scans from the dashboard.

### Hunting and investigation

- Log search and event explorer with a query builder (Elasticsearch, cursor pagination).
- Live events view with volume, auth failures, top sources and per-agent counts.
- Threat hunts by IP, hostname, user or SHA-256 across endpoint history, with schedules.
- Threat IoC search, process trees, source logs, and CSV/JSON alert export.
- Command center: live attack map (GeoIP) and attack feed, backlog/SLA matrix, noisiest rules,
  most-targeted hosts, and a **wall mode** for a SOC screen.
- Overview: quick indicator lookup against threat intel, analyst workload and recent activity.
- Alert detail: overview, process tree, table and raw JSON views, notes, and **Create case**.
  From the alert list you can hunt the indicator or add a suppression.
- Live response: **Collect** (run artifacts), saved **Artifacts**, and legacy tasks.
- Knowledge base: vault articles, quick notes, a payload reference (PayloadsAllTheThings), lessons
  learned from feedback, import, and a retrieval **Test** to see what the AI would find.

### Posture

- Hygiene per host: score, packages with vulnerable versions, open ports with risky ports
  flagged, disk and patch level.
- File Integrity Monitoring with paths managed from the dashboard.
- Developer/project compromise findings (`project_scan_*` rules).

### Platform

- **RBAC:** viewer < analyst < admin < superadmin. Users belong to a group and see only that
  group's agents, alerts and cases. Superadmins see everything.
- JWT with refresh tokens, **TOTP MFA**, and an audit log.
- Agent fleet management: enrollment tokens with approval, token rotation, uninstall tokens,
  tamper alerts, and **staged update rollouts** (rings, failure threshold, auto-pause).
- Integrations: webhooks to Slack, Teams, Discord, Jira and ServiceNow with retries, plus SMTP
  email.
- Shift handover notes, SOP library and knowledge base.
- Live alerts over WebSocket, an event stream over SSE, and Prometheus `/metrics`.
- `pg_dump` backups every `BACKUP_INTERVAL_HOURS` (default 24), and an Elasticsearch snapshot
  policy.
- Separate retention periods for raw logs, events and closed alerts (**Settings**, 0 = keep).
- **Settings** page: AI on/off and models, TI API keys (VirusTotal, AbuseIPDB, OTX, GreyNoise,
  Shodan, abuse.ch, PhishTank), case grouping window and IOC exclusions, UEBA engine and
  threshold, the SOAR HTTP allowlist, SMTP alerts, retention, and per-user MFA. Changes apply
  within 60 seconds.

### Dashboard

| Section | Pages |
|---|---|
| Operations | Overview, Command center, Alerts, Cases, Shift handover |
| Investigation | Log search, Events, Live events, Threat hunting, Threat IoCs, Behavior analytics (UEBA), Entity risk, Lateral movement, MITRE coverage |
| Response | Live response, SOAR workflows, Playbooks & SOPs, Knowledge base |
| Environment | Agents (log sources, firewall), Syslog devices, Agent updates, Security posture, File integrity, YARA, Prevention, Malware hashes, Web protection, IP Blocklist, Policies, Reports |
| Administration | Detection rules, Decoders, Integrations, Audit log, Users, Settings |

Global features: header search (Ctrl/Cmd+K), the SOC assistant on every page, and a live/polling
indicator.

## Architecture

```
 Linux / Windows endpoints                 Network & appliances
 ┌────────────────────────────┐            ┌──────────────────────────────┐
 │ siem-agent (Go)            │            │ Suricata / Zeek (IT + OT)    │
 │  eBPF / ETW sensors        │            │ FortiGate, CEF senders,      │
 │  RansomGuard, IOA, YARA,ML │            │ rsyslog from any host        │
 │  prevent, isolate, FIM     │            └──────────────┬───────────────┘
 │  live response, webblock   │                           │ syslog UDP/TCP 514
 └─────────────┬──────────────┘                           ▼
               │ HTTPS (enroll, logs,            ┌──────────────────┐
               │ heartbeat, tasks)               │ syslog-receiver  │
               ▼                                 └────────┬─────────┘
       nginx (TLS) ──► server-api (FastAPI) ──────────────┤
         ▲                │   REST · WebSocket · SSE      ▼
         │                │                        Redis Streams
   dashboard (React)      │                               │
                          │                               ▼
                          │                worker (Python asyncio)
                          │                 decoders → Sigma → alerts
                          │                 UEBA · TI · MalwareBazaar
                          │                 AI triage → case correlation
                          │                 SOAR engine · hunts · reports
                          ▼                               │
          PostgreSQL (pgvector) ◄────────────────────────┤
          Elasticsearch (logs, events) ◄──────────────────┘
                          │
                9router (LLM router) ─► cloud or local models
                searxng (web search for enrichment)
```

## Requirements

**Server host:**
- Linux x86_64 (tested on Debian/Kali; anything Docker-supported works)
- Docker Engine 24+ and the Docker Compose plugin (`docker compose`, not the old `docker-compose`)
- 4 vCPU / 8 GB RAM minimum (Elasticsearch + Postgres + 2× server-api + 2× worker); more for real traffic volumes
- Ports 80/443 free (nginx), plus 514 UDP/TCP for agentless syslog (configurable with `SYSLOG_PORT`)

**Endpoint agent host:**
- Linux, or Windows 10 / Server 2016 and later (see [Windows](#windows) — no macOS build)
- To run as a systemd service: any systemd-based distro (Debian/Ubuntu → `.deb`, RHEL/Fedora/Rocky/Alma → `.rpm`)
- For the eBPF sensors (optional, degrades gracefully without them):
  - Kernel with BTF: `ls /sys/kernel/btf/vmlinux` must exist (`CONFIG_DEBUG_INFO_BTF=y`) — true on any mainstream distro kernel from the last ~5 years
  - `CAP_BPF` + `CAP_SYS_ADMIN` (or root) — the agent already needs root for the firewall-based isolate/block-IP actions, so this isn't an extra ask in practice
- To build the agent from source: Go 1.25+ and `clang` (only needed at build time to compile the eBPF programs; the compiled objects are embedded into the binary)

## Services

| Service | Description | Port |
|---|---|---|
| `postgres` | Primary database (pgvector) | 5432 (internal) |
| `redis` | Ingest stream, queues, suppression/threshold counters | 6379 (internal) |
| `elasticsearch` | Raw log + decoded event store | 9200 (internal) |
| `server-api` | REST API, auth, agent ingest, WebSocket/SSE (2 replicas in prod) | 8000 (internal) |
| `worker` | Pipeline: decode → Sigma → alerts → AI triage → cases → SOAR, plus UEBA, TI, feeds, hunts, reports (2 replicas in prod) | 8001 (health only) |
| `syslog-receiver` | Agentless syslog / CEF listener (same image as the worker) | `${SYSLOG_PORT:-514}` UDP/TCP |
| `dashboard` | React SPA, built + served by its own nginx | 80 (internal) |
| `nginx` | Public reverse proxy, TLS termination | 80 / 443 |
| `9router` | LLM router for the AI analyst, investigator and assistant | 20128 (internal), 20129 (host) |
| `searxng` | Web search backend for enrichment | 8080 (internal) |
| `watchtower` | Daily pull of opted-in images (9router only, label-gated) | — |
| `backup` | Scheduled `pg_dump` backups | — |
| `package-builder` | One-shot: builds agent `.deb`/`.rpm`, then exits | — |
| `geoip-init` | One-shot: downloads the GeoIP database | — |
| `agent-demo` | Demo agent tailing the host's own `/var/log` | — |
| `attacker` | Dev-only lab attacker (`docker-compose.dev.yml`, `sim/attacker`) | — |

## Server Installation

```bash
git clone <repo>
cd ADSIEM  # or siem-platform, whatever you cloned it as
cp .env.example .env
```

**1. Fill in secrets in `.env`** — at minimum:

```bash
JWT_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=<strong password>
AGENT_ENROLLMENT_TOKEN=<strong random token>
```
Also update `DATABASE_URL` to match if you changed `POSTGRES_PASSWORD`.

**2. Generate a TLS certificate.** If you have a real domain pointed at this host, use
Let's Encrypt/certbot instead of the steps below. For a self-signed cert (dev, or an
internal-only deployment), it **must** include a `subjectAltName` for however clients
will actually reach it (IP and/or hostname) and `basicConstraints = CA:TRUE` — plain
`openssl req -x509` with just a `CN` will silently fail both browser/curl validation
*and* `update-ca-trust`/`update-ca-certificates` trust-anchor import on agent hosts:

```bash
mkdir -p nginx/certs
cat > /tmp/san.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = <your-server-ip-or-hostname>

[v3_req]
subjectAltName = @alt_names
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign

[alt_names]
IP.1 = <your-server-ip>
DNS.1 = <your-server-hostname-if-any>
EOF

openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout nginx/certs/key.pem -out nginx/certs/cert.pem \
  -config /tmp/san.cnf -extensions v3_req
```

**3. Start the stack:**

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

First start takes a few minutes (Elasticsearch + Postgres init, image builds). Watch it come up:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
# everything should reach "healthy" within ~60s once images are built
```

**4. Log in.** Open `https://<your-server>` — `admin` / `admin123` — then immediately
change the admin password (**Settings → Users**).

For local development instead of a production deploy, see [Development](#development) below.

## Development

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

- API hot-reloads from `server-api/app/`
- Dashboard hot-reloads from `dashboard/src/` on port 5173
- Postgres exposed on 5432, Redis on 6379
- Plain HTTP on port 80 (no TLS cert needed for dev)

## Agent Installation

The agent is a single static Go binary for Linux and Windows. The quickest way onto a
host is the dashboard's deploy command; the options below cover doing it by hand.

### Deploy from the dashboard (recommended)

**Agents → Deploy agent** works like Wazuh's *Deploy new agent*. You pick the OS
(DEB, RPM or Windows), check the server address the host will use, and create an
**enrollment key**. You then get one command to run on the host, which downloads the
package from this server, installs it, enrolls the agent and starts it:

```bash
curl -fsSLo /tmp/siem-agent_1.27.3_amd64.deb 'https://siem.example.com/api/agents/packages/siem-agent_1.27.3_amd64.deb' \
  && sudo SIEM_SERVER_URL='https://siem.example.com' SIEM_ENROLLMENT_KEY='<key>' dpkg -i /tmp/siem-agent_1.27.3_amd64.deb
```

The RPM command is the same with `rpm -Uvh`. On Windows, an elevated PowerShell
downloads the zip and runs `install.ps1 -ServerUrl … -EnrollmentToken …`.

**Enrollment keys** (Agents → Deploy agent, or `POST /api/enrollment-tokens`):

- A key decides the agent's **group**. A group-scoped admin can only create keys for
  their own group.
- *Max agents*: `1` gives a single-use key. A number allows that many hosts. Blank means
  unlimited, which suits a deployment key you paste into Ansible, GPO or a golden image.
  Uses are counted atomically, so parallel installs can't go over the limit.
- *Expires in* and **revoke** limit how long a key can be used. Revoking a key doesn't
  touch agents already enrolled with it.
- *New agents wait for approval*: agents enrolled with such a key show as **PENDING**.
  Their heartbeats are accepted, but their logs are dropped and they get no
  live-response tasks until someone clicks **Approve**. Wazuh's open enrollment has no
  equivalent; it trusts anyone holding the password.

Re-enrolling a hostname reuses that agent's record, so a rebuilt host doesn't leave a
duplicate behind. This is only allowed once the old agent has been silent for 2 minutes.
While it is still connected the server answers 409 and the new install keeps retrying.
This stops anyone holding a key from taking over a live agent by reporting its hostname.

### Option A — Prebuilt package (`.deb` / `.rpm`)

The platform builds the packages on every stack start: the `package-builder` service
runs the same scripts as the release, at the version in `agent/VERSION`. The dashboard
serves them, and so does each tagged GitHub release
(`.github/workflows/agent-release.yml`, triggered by a tag like `agent-v1.27.3`).

```bash
sudo dpkg -i siem-agent_<version>_amd64.deb          # or: sudo rpm -Uvh siem-agent-<version>-1.x86_64.rpm
sudo siem-agent-configure --server https://siem.example.com --key <enrollment key>
```

`siem-agent-configure` writes the server and key into `/etc/siem-agent/config.yaml`,
clears any earlier enrollment, and on RHEL-family hosts switches the log paths to
`/var/log/secure` and `/var/log/messages`. It then enables and starts the service. Run
it again whenever an installed agent should point at another server. Setting
`SIEM_SERVER_URL`/`SIEM_ENROLLMENT_KEY` (and optionally `SIEM_AGENT_NAME`) while
installing the package does the same thing, which is what the one-line command relies on.

Both packages install to `/usr/bin/siem-agent`, `/etc/siem-agent/config.yaml`, and a
`siem-agent.service` unit. The packaged `postinst` creates an unprivileged `siem-agent`
system user — but note the unit file as shipped runs the agent with no `User=` directive,
i.e. **as root**, which is what live-response (`iptables` isolate/block-IP) and the eBPF
monitor need. If you harden the unit to run as `siem-agent`, isolate/block-IP and
process-exec monitoring will fail closed (logged as warnings, not fatal) — everything
else (log tailing, FIM, hygiene) still works unprivileged.

### Windows

Each tagged release ships **`siem-agent-<version>-x64.msi`**. It is built with WiX on a
Windows runner, and before publishing the release workflow installs it there and
checks enrollment and event shipping (`tests/windows/smoke-msi.ps1`). Install it like
Wazuh's, from an elevated prompt or any deployment tool (Intune, SCCM, PDQ…):

```powershell
msiexec /i siem-agent-<version>-x64.msi /qn SERVER_URL=https://siem.example.com ENROLLMENT_KEY=<key> ENABLE_AUDITING=1
```

| Property | |
|---|---|
| `SERVER_URL` | SIEM server, as the host reaches it (required on first install) |
| `ENROLLMENT_KEY` | enrollment key (required on first install; a new one re-enrolls the agent) |
| `AGENT_NAME` | optional, default: hostname |
| `ENABLE_AUDITING` | `1` turns on logon / process-creation (with command line) / account auditing and PowerShell script block logging |

The MSI installs `C:\Program Files\SIEMAgent\siem-agent.exe` as the auto-start
`SIEMAgent` service. The service runs as LocalSystem and restarts itself if it crashes.
Its config and `agent.log` live in `C:\ProgramData\SIEMAgent`, which only SYSTEM and
Administrators can read.

- **Upgrade:** a newer MSI, with or without properties, keeps the config and the agent token.
- **Uninstall:** `msiexec /x` or *Apps & features* removes the service and binary and
  leaves `C:\ProgramData\SIEMAgent`.
- **Re-point an agent** at another server without reinstalling:
  `siem-agent.exe -configure -server … -key …`.

The release also has the older `siem-agent-windows-amd64-<version>.zip`, holding the exe,
`install.ps1` and `uninstall.ps1`, for hosts where an MSI can't be used:
`powershell -ExecutionPolicy Bypass -File install.ps1 -ServerUrl … -EnrollmentToken … -EnableAuditing`.

The agent reads the Security, System, Application, Sysmon and PowerShell/Operational event
logs (log source paths `eventlog:<channel>`), decoded by `decoders/win_*.yaml`. `-EnableAuditing`
turns on logon / process-creation (with command line) / account-management auditing and
PowerShell script block logging; install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
for process, network, file, registry and DNS events. Live response has its own `Windows.*`
artifacts:

- **System:** info, processes, connections, users, persistence (Run keys, Startup folder, tasks,
  services, WMI), services, installed programs.
- **Detection and search:** suspicious processes (encoded PowerShell, LOLBins, tools, user-writable
  paths), file finder/hash, executables in user folders, YARA, Prefetch.
- **Event log queries over the history already on the host:** a generic channel + event-ID query,
  failed logons, RDP logons, service installs, PowerShell script blocks, cleared logs, Defender
  detections.

Host isolation and block-IP use Windows Defender Firewall.
Hygiene works too: OS and build, memory, disks, listening ports, local accounts, installed programs (Add/Remove Programs), plus Windows checks: firewall profiles, Defender real-time protection, UAC, SMBv1, Guest account, RDP without NLA. Installed programs aren't CVE-scanned, since OSV has no Windows ecosystem. There is no eBPF process monitor on Windows.

### Option B — Build from source

```bash
cd agent
go build -ldflags="-s -w" -o siem-agent ./cmd/agent/
```

This alone is enough for log tailing / FIM / hygiene / live-response. The eBPF
process-exec monitor additionally needs its bytecode object compiled first
(`go:embed` pulls it in at build time — the binary won't build without it):

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I internal/procexec/bpf/include \
  -c internal/procexec/bpf/execve.bpf.c \
  -o internal/procexec/bpf/execve.bpf.o
# then: go build ...
```
(`-D__TARGET_ARCH_arm64` on arm64 hosts.) `make build` in `agent/` runs the clang
step itself (target `bpf`) before the Go build, and fails with a clear message if
`clang` is missing — so the manual command above is only needed for a bare
`go build`. The compiled `.bpf.o` is gitignored; never commit it.

### Option C — Docker

```bash
docker run -d \
  -e AGENT_ENROLLMENT_TOKEN=<your-token> \
  -v /var/log:/host/var/log:ro \
  -v $(pwd)/config.yaml:/app/config.yaml \
  --network host \
  --privileged \
  siem-agent:latest
```
`--privileged` (or at least `--cap-add=BPF --cap-add=SYS_ADMIN --cap-add=NET_ADMIN`) is
needed for the eBPF monitor and live-response actions; omit it if you only need log
shipping and accept those features being disabled.

### config.yaml reference

```yaml
agent:
  id: host-001              # stable unique ID; set once, don't change after enrollment
  name: my-webserver
  group: production          # controls dashboard visibility for non-superadmin users
  token: ""                  # filled in automatically after first successful enrollment
  buffer_size: 10000

server:
  url: https://<your-server>   # MUST match the scheme nginx actually serves — see Troubleshooting
  heartbeat_interval: 30

logs:
  - path: /var/log/auth.log
    type: linux_auth
  - path: /var/log/syslog
    type: syslog
  # glob patterns are supported for daily-rotated logs, e.g. /var/log/nginx/access.log*

fim:
  enabled: true
  watch_paths:
    - /etc
    - /usr/bin
```

Run with `AGENT_ENROLLMENT_TOKEN=<matches server's .env value> ./siem-agent -config config.yaml`
the first time — enrollment happens automatically and the agent writes its issued
`token` back into `config.yaml`. After that, log sources and FIM paths can be managed
live from the dashboard (**Agents → [agent name] → Log Sources**) without touching the
config file again; `RELOAD_INTERVAL` on the worker and the agent's heartbeat loop keep
both sides in sync.

### Trusting a self-signed platform certificate

If the platform's TLS cert isn't from a public CA (see step 2 of
[Server Installation](#server-installation)), every agent host needs that cert added to
its own trust store, or all agent→server traffic will fail TLS verification. On Windows
the download in the install command fails first, with *Could not establish trust
relationship for the SSL/TLS secure channel*.

**Agents → Deploy agent handles this.** nginx serves the certificate (not the key) at
`/api/agents/platform-ca.pem`, and the wizard puts it into the command it generates, so
the host trusts it before downloading anything:

- Windows: imports into `LocalMachine\Root`.
- Debian: `update-ca-certificates`.
- RHEL: `update-ca-trust`.

For an `https://<IP>` server this is on by default. The wizard shows the certificate's
SHA-256 fingerprint; check it against
`openssl x509 -noout -fingerprint -sha256 -in nginx/certs/cert.pem` on the server.

By hand:

```bash
# fetch the cert from the server, e.g.:
scp server:/path/to/ADSIEM/nginx/certs/cert.pem ./adsiem-ca.pem
```

**Debian/Ubuntu/Kali:**
```bash
sudo cp adsiem-ca.pem /usr/local/share/ca-certificates/adsiem-platform.crt
sudo update-ca-certificates
```

**RHEL/Fedora/Rocky/Alma:**
```bash
sudo cp adsiem-ca.pem /etc/pki/ca-trust/source/anchors/adsiem-platform.pem
sudo update-ca-trust extract
```

**Windows** (elevated PowerShell):
```powershell
Import-Certificate -FilePath .\adsiem-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

Then restart the agent: `sudo systemctl restart siem-agent` (Windows: `Restart-Service SIEMAgent`).

### Verifying an agent is fully working

```bash
sudo journalctl -u siem-agent -f
```

Look for, in order: `tailing` lines (log sources picked up), `procexec: attached to
tracepoint/syscalls/sys_enter_execve` (eBPF monitor active — its absence is non-fatal,
just means that signal isn't available on this host), then steady `buffer stats`
lines with `len` staying near 0 and `pushed`≈`popped` (meaning the server is actually
accepting what's being sent — a growing `len` or repeated `send failed`/`heartbeat
failed` errors mean connectivity or TLS trust is broken, see Troubleshooting).

To confirm detections are reaching the pipeline end-to-end, trigger something a
shipped rule matches and check for the resulting alert, e.g. (safe — doesn't actually
load a kernel module):
```bash
echo not-a-real-module > /tmp/t.ko && sudo insmod /tmp/t.ko   # fails harmlessly
rm /tmp/t.ko
```
then check **Alerts** in the dashboard, or:
```bash
curl -H "Authorization: Bearer $TOKEN" "http://localhost/api/alerts?search=Kernel+Module"
```

## RBAC

| Role | Capabilities |
|---|---|
| `superadmin` | Full access, including user management, across all groups |
| `admin` | Settings, agent log sources and firewall rules, integrations, audit log, rules and decoders |
| `analyst` | Triage alerts and cases, edit SOAR playbooks and approve runs, web protection |
| `viewer` | Read-only |

Roles are ordered viewer < analyst < admin < superadmin. Each user belongs to one group and only
sees that group's agents, logs, alerts and cases; superadmin sees all. Starting an AI
investigation needs `cases:manage` plus `agents:manage`. Accounts can enable TOTP MFA.

## Adding Rules

Rules live in `rules/*.yaml` and are auto-seeded into the database on worker startup
(new files only — existing rules by `title` are left alone, so editing a rule in the
dashboard after seeding won't get clobbered by a redeploy). They're plain Sigma:

```yaml
title: My Rule
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
```

Field names are whatever your decoder emits — this repo mostly uses ECS-style dotted
fields (`event.action`, `user.name`, `source.ip`), **except** the `process_creation`
logsource (from `linux_process_exec` / the eBPF monitor), which intentionally uses
Sigma's own standard field names (`Image`, `CommandLine`, `ParentImage`, `User`,
`ProcessId`, `ParentProcessId`) instead of ECS — that's what lets you drop in public
SigmaHQ `process_creation` rules unmodified.

Besides Sigma's own `threshold`-like correlations, rules can use an `after:` block: the rule
fires only when at least `count` events matching `after.detection` were seen for the same
`group_by` values within `timewindow`. For example, `rules/login_after_brute_force.yaml` fires
on a successful login preceded by five or more failures from the same `source.ip`. Each
sequence fires once.

A rule only sees events from its `logsource` (`worker/worker/sigma_logsource.py` maps
each decoder `log_type` — plus, for Windows, the event's channel and EventID — to
Sigma's product/service/category; any other `log_type` like `fortigate_traffic` is
read as product `fortigate`, service `traffic`). Rules without a logsource see every event.

### SigmaHQ ruleset

**Dashboard → Rules → Import SigmaHQ** downloads an official
[SigmaHQ release](https://github.com/SigmaHQ/sigma/releases) (Core, Core+, Core++,
Emerging Threats or All) and imports it; servers without internet access can upload
the release zip instead. Run it again to update: rules are matched by their Sigma id,
upstream changes are applied, and rules you edited in the dashboard are left alone.
New rules are enabled when their level and status pass the policy you pick (default:
high/critical, stable/test) and a log source here can feed them — cloud, macOS and
other sources the agents don't collect are imported disabled and marked
*not collected*.

Windows events keep their native field names (Sysmon/Security `EventData`, e.g.
`Image`, `TargetObject`, `NewValue`), so SigmaHQ's Windows rules run unmodified.
Compatibility is checked by replaying SigmaHQ's own regression samples — real `.evtx`
events paired with the rule that must match — through agent formatting → decoders →
engine (`tests/sigmahq/run.sh`, `.github/workflows/sigmahq-compat.yml`): all 3,768
rules load and 469/471 samples give the exact expected match count (the other two
samples hold two matching events where the reference counts one).

Also addable via API or **Dashboard → Rules → New Rule** (write YAML → Test → Save):
```bash
curl -X POST http://localhost/api/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My Rule",
    "content": "title: My Rule\ndetection:\n  selection:\n    event.action: login_failed\n  condition: selection\nlevel: medium",
    "level": "medium"
  }'
```

## Adding Decoders

Same seeding mechanism as rules, from `decoders/*.yaml`. Two types:

**regex** — named capture groups map to output fields:
```yaml
name: my_decoder
log_type: linux_auth
type: regex
priority: 50
enabled: true
pattern: 'Failed password for (?P<user>\S+) from (?P<src_ip>\S+)'
fields:
  event.action: login_failed
  user.name: user
  source.ip: src_ip
```

**kv** — for `key=value` / `key="quoted value"` formatted logs (FortiGate-style, and
what the eBPF process-exec events use):
```yaml
name: my_kv_decoder
log_type: some_log_type
type: kv
priority: 10
fields:
  event.action: action   # output_field: kv_key
static_fields:
  event.category: network
```

**json** — one JSON object per line (Suricata, Zeek, cloud and app logs). `fields` maps
output fields to dotted paths (a list gives fallbacks), `when` selects records
(`path: value`, `path: [a, b]`, or `path: "*"` for "exists"), and `raw_fields: true` keeps
every source field as well. The JSON can follow a syslog header:
```yaml
name: suricata_eve_alert
log_type: suricata
type: json
priority: 10
when:
  event_type: alert
fields:
  source.ip: src_ip
  destination.ip: dest_ip
```

**cef** — ArcSight CEF from any vendor (`decoders/cef_generic.yaml`). For vendor-specific
mappings, add a `type: cef` decoder with the same `log_type`, a priority below 50 and
`match: <vendor name>`.

Also addable via **Dashboard → Decoders → New Decoder** (Test with a raw log line → Save).
Decoders and rules added in the dashboard take effect on the worker's next reload
(`RELOAD_INTERVAL`), with no redeploy.

## Syslog, Suricata, Zeek and OT

Anything that can send syslog can feed ADSIEM without an agent.

1. **Environment → Syslog devices → Add**: give the sender's IP or CIDR and a log type
   (`fortigate_traffic`, `cef`, `suricata`, `zeek`, `linux_auth`, `syslog`, or your own).
   Messages from unregistered addresses are dropped and listed with a sample, so you can
   register them.
2. Point the device at `<siem-host>:514` (UDP or TCP).

Suricata and Zeek write one JSON object per line. Either let the agent on the sensor tail the
file, or forward it with rsyslog (`/etc/rsyslog.d/91-suricata.conf`):

```
module(load="imfile")
input(type="imfile" File="/var/log/suricata/eve.json" Tag="suricata" Severity="info")
if $programname == 'suricata' then @@<siem-host>:514
```

**OT / ICS networks.** PLCs, RTUs and relays cannot run an agent, so monitor them from the
network. Put a Suricata sensor on a mirror (SPAN) port of the OT segment, with the `modbus`
and `dnp3` app-layer parsers and EVE output enabled, and forward `eve.json` as above.
`suricata_eve_generic` ingests every record type, so Modbus/DNP3 transactions arrive with
`network.protocol: modbus|dnp3`, `event.action` set to the EVE type, and source and
destination addresses. Suricata alerts on OT signatures arrive through `suricata_eve_alert`.
Run the agent on the Windows/Linux hosts around the process (HMI, SCADA server, historian,
engineering workstation).

To alert on specific Modbus operations, map the function code with a decoder in the dashboard,
then write rules against it. Check the exact EVE field names against your Suricata version,
and test the decoder with a sample record before enabling the rule:

```yaml
# Decoders → New Decoder
name: suricata_eve_modbus
log_type: suricata
type: json
priority: 20
when:
  event_type: modbus
fields:
  source.ip: src_ip
  destination.ip: dest_ip
  network.protocol: app_proto
  modbus.function_code: modbus.request.function_raw
  modbus.unit_id: modbus.request.unit_id
static_fields:
  event.action: modbus
---
# Rules → New Rule
title: Modbus write from a host that is not an HMI
logsource:
  product: suricata
detection:
  write:
    event.action: modbus
    modbus.function_code: ['5', '6', '15', '16']
  hmi:
    source.ip: ['10.20.0.10', '10.20.0.11']   # your HMIs / engineering workstations
  condition: write and not hmi
level: high
tags:
  - attack.t0855   # ATT&CK for ICS: Unauthorized Command Message
```

Full runbook: [`docs/operations/syslog-ingest.md`](docs/operations/syslog-ingest.md).

## API Examples

```bash
# Login
curl -c cookies.txt -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# List alerts
curl -H "Authorization: Bearer $TOKEN" http://localhost/api/alerts

# Update alert status
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"resolved"}' \
  http://localhost/api/alerts/<alert-id>

# Test a decoder
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"..yaml..","raw_message":"May 21 sshd: Failed password for root from 1.2.3.4 port 22"}' \
  http://localhost/api/decoders/test
```

## Production Deployment

1. Set strong values for **all** secrets in `.env` (`JWT_SECRET`, `POSTGRES_PASSWORD`,
   `AGENT_ENROLLMENT_TOKEN`, `NINEROUTER_*`, `SEARXNG_SECRET`) and change the default
   admin password after first login.
2. Get a real TLS cert if you have a domain (Let's Encrypt); otherwise generate a
   self-signed one **with SAN + `CA:TRUE`** as shown in
   [Server Installation](#server-installation) — a bare `openssl req -x509 -subj
   "/CN=..."` will break both agent TLS verification and later `update-ca-trust`
   import in ways that fail silently/confusingly.
3. Start with the prod override (adds resource limits and `server-api`/`worker` replicas):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```
4. Point every agent's `config.yaml` `server.url` at `https://...`, not `http://...`
   — nginx 301-redirects HTTP→HTTPS, and Go's HTTP client downgrades POST to GET when
   following a 301, which turns every log/heartbeat POST into a 405. Using `https://`
   directly avoids the redirect hop entirely.
5. Install the platform's CA cert on every agent host if it's self-signed (see
   [Trusting a self-signed platform certificate](#trusting-a-self-signed-platform-certificate)).
6. Confirm both `worker-1` and `worker-2` logs are clean on first boot
   (`docker compose logs worker | grep -i fail`) — decoder/rule seeding races
   between replicas are handled with per-item `SAVEPOINT`s, but it's worth a glance
   after adding a batch of new rules/decoders.

## Observability

- Health: `GET https://<your-server>/health`
- Metrics (Prometheus): `GET https://<your-server>/metrics`
- Worker health: `docker compose exec worker curl http://localhost:8001/health`
- Logs: `docker compose logs -f worker` / `docker compose logs -f server-api`
- Per-service status: `docker compose -f docker-compose.yml -f docker-compose.prod.yml ps`

## Troubleshooting

**Agent not enrolling:** Check `AGENT_ENROLLMENT_TOKEN` matches between `.env` on the
server and the agent's environment/config at first run.

**Agent logs `tls: failed to verify certificate: ... doesn't contain any IP SANs`:**
The server's cert has no `subjectAltName` covering how the agent connects (IP vs
hostname). Regenerate it with a proper SAN (see Server Installation) — `CN` alone is
not enough for modern TLS clients, Go included.

**Agent logs `tls: failed to verify certificate: ... signed by unknown authority`:**
The cert is valid but self-signed and this host doesn't trust it yet. Also check that
the cert itself has `basicConstraints = CA:TRUE` — without it, `update-ca-trust`/
`update-ca-certificates` will silently drop it from the trust bundle even though it's
sitting right there in `source/anchors/`. See
[Trusting a self-signed platform certificate](#trusting-a-self-signed-platform-certificate).

**Agent logs repeated `POST ... 301` immediately followed by `GET ... 405`:**
`server.url` in the agent's config is `http://`, and nginx is redirecting to HTTPS —
Go's client follows the redirect but downgrades the method. Change `server.url` to
`https://` directly.

**`procexec: <error>` warning on agent startup, or no `procexec: attached` line at all:**
Non-fatal by design — the eBPF monitor needs a BTF-enabled kernel
(`/sys/kernel/btf/vmlinux` must exist) and `CAP_BPF`/`CAP_SYS_ADMIN` (root). Everything
else keeps working without it.

**No alerts generated:** Check worker logs (`docker compose logs worker`). Verify
decoders and rules are seeded (`GET /api/decoders`, `GET /api/rules`), and that the
relevant log's `log_type` actually has a decoder — an ingested log with no matching
decoder produces an empty event dict, which no rule will match.

**Dashboard 502:** Ensure server-api is healthy (`docker compose ps`).

**Database connection refused:** Wait for postgres healthcheck to pass (up to 30s on first start).

**nginx container stuck restarting, log says `cannot load certificate ".../cert.pem"`:**
`nginx/certs/cert.pem`/`key.pem` don't exist yet — generate them (Server Installation
step 2) before bringing up `nginx` in the prod compose.

## Documentation

Runbooks live in [`docs/operations/`](docs/operations/):

| Area | Runbooks |
|---|---|
| Detection | `ioa`, `yara`, `static-ml`, `malware-hashes`, `detection-benchmark`, `policies`, `alert-statuses` |
| Behaviour analytics | `behavior-baselines`, `entity-risk`, `lateral-movement` |
| Endpoint protection | `anti-ransomware`, `exec-prevention`, `app-control`, `ip-ioc-blocking`, `script-scan`, `file-scan`, `memory-scan`, `process-tree`, `host-isolation`, `web-protection` |
| Ingest and agents | `agent-config-recommended`, `syslog-ingest`, `linux-sensor`, `windows-sensor`, `agent-self-update`, `agent-tamper` |
| Agent evidence | `agent-evidence-recovery`, `agent-evidence-validation`, `agent-evidence-progress` |
| Platform | `backup-restore`, `token-lifecycle`, `ai-triage-retry` |

Design references: [`docs/CASE_CORRELATION.md`](docs/CASE_CORRELATION.md) (IOC-keyed case model),
[`docs/llm-gateway-spec.md`](docs/llm-gateway-spec.md), [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md),
and dated specs and plans in `docs/superpowers/`.

## Testing and CI

- **Python:** `tests/worker/` and `tests/server-api/` (pytest, roughly 150 files), the evidence
  acceptance harness in `tests/evidence/`, and Playwright UI checks in `tests/dashboard/`.
- **Go:** unit tests across `agent/` and `tests/agent/`, run with `go test -race`.
- **SigmaHQ compatibility:** `tests/sigmahq/run.sh` replays SigmaHQ's regression samples through
  agent formatting → decoders → engine.
- **CI** (`.github/workflows/`):
  - `ci.yml`: pytest, Go race tests, and privileged Linux end-to-end suites (sensor, web
    block, prevention, ransomware, memory scan, credential watch), plus agent self-update,
    the evidence matrix, and the dashboard type check and build.
  - `windows-agent.yml`: MSI smoke tests, evidence resume, and memory-scan and task tests on
    Windows.
  - `agent-release.yml`: signed release packages on `agent-v*` tags.
  - `sigmahq-compat.yml`: weekly SigmaHQ replay.

Supporting tools: `ml/` trains the static ML model, `sim/attacker` is a dev-only attack lab,
and `scripts/` holds backup, GeoIP update and Let's Encrypt renewal helpers.

## Roadmap

- [x] Real-time dashboard via WebSocket
- [x] Email notification integration
- [x] Prometheus `/metrics` endpoint
- [ ] Grafana dashboard
- [x] One-command agent deployment with reusable enrollment keys and approval
- [x] Agent self-update with signed packages and staged rollouts
- [x] Windows endpoint agent
- [x] Sigma rule import from community repos (SigmaHQ)
- [x] Agentless syslog / CEF ingest, Suricata and Zeek decoders
- [x] AI triage, AI case correlation and autonomous investigator
- [ ] Bundled Modbus / DNP3 decoders and ICS rule pack
- [ ] Bahasa Indonesia dashboard UI (AI reports already support it)
- [ ] Multi-tenancy group management UI
- [ ] macOS endpoint agent
- [ ] Let's Encrypt automation (a cron renewal script exists in `scripts/renew-letsencrypt.sh`)
