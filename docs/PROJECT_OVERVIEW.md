# ADSIEM — Project Overview

Platform SIEM (Security Information and Event Management) open-source yang dibangun untuk hackathon. Mencakup pengumpulan log dari endpoint, deteksi ancaman berbasis aturan, analitik perilaku (UEBA), threat intelligence, dan dashboard SOC.

---

## Arsitektur Keseluruhan

```
[Endpoint / Server]
     |
  siem-agent (Go binary)
     | tails log files
     | POST /api/ingest/log  (X-Agent-Token header)
     v
[server-api] ──────────────────────────────── FastAPI + PostgreSQL
     | enqueue ke Redis Stream
     v
[worker] ─────────────────────────────────── Python async consumer
     ├── decoder_engine   (regex → structured fields)
     ├── sigma_engine     (rule matching + threshold + suppression)
     ├── alert_manager    (create alert + fire webhook)
     ├── ueba/scorer      (Isolation Forest anomaly scoring)
     └── ti/aggregator    (threat intelligence enrichment)
     v
[dashboard] ─────────────────────────────── React + Vite (SOC UI)
```

**Infrastruktur:** PostgreSQL 16, Redis 7, Nginx (reverse proxy), SearXNG (search engine untuk AI analyst)

---

## Komponen

### 1. Agent (`agent/`) — Go 1.22

Lightweight binary yang di-deploy ke setiap endpoint yang ingin dipantau.

| Fitur | Detail |
|-------|--------|
| Log tailing | `bufio.Reader` follow-mode, hot-reload log sources dari heartbeat |
| Enrollment | Satu kali pakai enrollment token → dapat `agent_id` + `agent_token` permanen |
| Heartbeat | Setiap 30s, terima update log sources + FIM paths + task dispatch |
| File Integrity Monitoring | `fsnotify` watch paths dari server |
| IT Hygiene | Kirim info OS, CPU, memory, running services |
| Live Response | Terima task dari server (artifact collection, YARA scan, isolasi jaringan) |
| Buffer | In-memory queue dengan exponential backoff, re-queue saat server down |

**Instalasi (v1.1.0):**
```bash
# Install .deb
dpkg -i siem-agent_1.1.0_amd64.deb

# Edit config
vim /etc/siem-agent/config.yaml
# Set server.url dan agent.enrollment_token

# Start
systemctl start siem-agent
```

**Build:**
```bash
VERSION=1.1.0 bash packaging/build-deb.sh   # → dist/packages/siem-agent_1.1.0_amd64.deb
VERSION=1.1.0 bash packaging/build-rpm.sh   # → dist/packages/siem-agent-1.1.0-1.x86_64.rpm
```

---

### 2. Server API (`server-api/`) — FastAPI + SQLAlchemy async

REST API utama. PostgreSQL sebagai database, Redis sebagai message queue.

**Endpoint utama:**

| Grup | Path | Fungsi |
|------|------|--------|
| Ingest | `POST /api/ingest/log` | Terima log dari agent → enqueue ke Redis |
| Ingest | `POST /api/ingest/heartbeat` | Heartbeat agent, return config update |
| Agent | `POST /api/agent/enroll` | Enrollment agent baru dengan enrollment token |
| Auth | `POST /api/auth/login` | Login user → JWT |
| Alerts | `GET/POST /api/alerts` | CRUD alert |
| Cases | `GET/POST /api/cases` | Case management |
| Events | `GET /api/events` | Event browser |
| Rules | `GET/POST /api/rules` | Sigma rules CRUD |
| Decoders | `GET/POST /api/decoders` | Decoder YAML CRUD |
| UEBA | `GET /api/ueba/...` | Entity scores, anomaly timeline |
| Webhooks | `GET/POST /api/webhooks` | Konfigurasi webhook notifikasi |
| AI Analyst | `POST /api/ai/...` | Chat analyst dengan konteks alert/case |

**Autentikasi:** JWT untuk user (dashboard), `X-Agent-Token` header untuk agent.

**Auto-create tables:** Semua tabel PostgreSQL dibuat otomatis saat startup jika belum ada.

---

### 3. Worker (`worker/`) — Python async (asyncio)

Consumer Redis Stream yang memproses setiap log masuk.

**Pipeline per log:**
```
Redis Stream
  → RawLog disimpan ke DB
  → DecoderEngine.decode()    → structured fields
  → Event disimpan ke DB
  → SigmaEngine.evaluate()    → rule matches
  → create_alert() + webhook  → untuk setiap match
  → ueba/scorer.score_event() → update entity risk score
```

**Sub-modul:**

#### Decoder Engine
- Memuat decoder dari DB (format YAML dengan regex)
- Field `fields_map`: nama group regex → nama field ECS
- Field `static_fields`: nilai tetap (misal `event.category: authentication`)
- Priority: decoder dengan priority lebih rendah dicoba lebih dulu
- Hot-reload setiap `RELOAD_INTERVAL` detik

#### Sigma Engine
- Rule format mirip Sigma (detection + condition + threshold + suppression)
- Modifiers field: `contains`, `startswith`, `endswith`, `re`
- Condition: `and`, `or`, `not` antar selection
- Threshold: `count + timewindow + group_by` — counter di Redis, alert saat melampaui batas
- Suppression: cooldown per entity setelah alert terpicu

#### UEBA (User and Entity Behavior Analytics)
- **Scorer** (`ueba/scorer.py`): Isolation Forest anomaly detection, model dimuat dari Redis
- **Trainer** (`ueba/trainer.py`): Melatih model dari data historis Redis counter
- **Features** (`ueba/features.py`): Vektor fitur untuk user (login count, failed ratio, hour-of-day, dll) dan IP
- Alert UEBA: risk score 0–100, cooldown 30 menit, min 3 anomali sebelum alert (cold entity guard)
- Model di-cache 5 menit di memory, disimpan di Redis sebagai base64 pickle

#### Threat Intelligence (`ti/`)
- **Providers:** AbuseIPDB, VirusTotal, OTX (AlienVault), GreyNoise, URLhaus, GeoIP, Whois
- **Extractor:** Parse IOC (IP, domain, URL, hash) dari teks bebas
- **Aggregator:** Jalankan semua provider paralel, susun summary teks
- **MITRE ATT&CK:** Mapping teknik dan taktik

#### AI Analyst
- Groq API (LLM) untuk chat analyst
- SearXNG untuk web search dalam konteks investigasi
- Akses ke alert, event, case sebagai konteks

---

### 4. Dashboard (`dashboard/`) — React + Vite + TypeScript

SPA yang mengonsumsi Server API. UI utama SOC analyst.

**Halaman:**

| Halaman | Fungsi |
|---------|--------|
| Dashboard | Ringkasan alert, event count, agent status |
| Alerts | List alert dengan filter severity/status |
| Cases | Case management (buka, tutup, tambah evidence) |
| Events | Browser event terstruktur |
| Logs | Raw log viewer |
| Agents | Status agent, log sources, FIM paths |
| UEBA | Entity risk scores + anomaly timeline |
| Hunts | Threat hunting query |
| Live Response | Dispatch artifact collection / YARA scan ke agent |
| Rules | CRUD Sigma rules |
| Decoders | CRUD decoder YAML |
| Log Sources | Konfigurasi sumber log per agent |
| FIM | File integrity monitoring events |
| Artifacts | Hasil live response |
| Hygiene | IT hygiene info dari endpoint |
| YARA | YARA rule management |
| Webhooks | Konfigurasi notifikasi (Slack, Teams, dll) |
| Settings | Konfigurasi platform |
| Users | User management |

**Auth:** JWT disimpan di Zustand store. Role: `admin`, `analyst`, `viewer`.

---

### 5. Decoders (`decoders/`) — YAML

Regex patterns untuk mengurai log menjadi field ECS (Elastic Common Schema).

**Log types yang didukung:**

| Log Type | File Log |
|----------|----------|
| `linux_auth` | `/var/log/auth.log`, `/var/log/secure` |
| `syslog` | `/var/log/syslog`, `/var/log/messages` |
| `nginx_access` | `/var/log/nginx/access.log` |
| `apache_access` | `/var/log/apache2/access.log` |
| `windows_security` | Windows Event Log |
| `windows_sysmon` | Sysmon Event Log |
| `linux_audit` | `/var/log/audit/audit.log` |

**SSH decoders tersedia:**
- `linux_auth_failed` — Failed password (termasuk invalid user)
- `ssh_invalid_user` — Invalid user attempts
- `ssh_disconnected_preauth` — Disconnect sebelum auth
- `ssh_pam_auth_failure` — PAM failures dengan IP
- `ssh_accepted` — Successful login
- `sudo_failed` / `linux_sudo` — Sudo events

---

### 6. Rules (`rules/`) — YAML (format Sigma-like)

75+ detection rules yang sudah tersedia.

**Kategori:**
- **SSH/Auth:** Brute force, root login, user enumeration, password spray, key addition
- **Web attacks:** SQLi, XSS, SSRF, RCE, Log4Shell, Spring4Shell, Shellshock, SSTI, XXE
- **Linux:** Persistence (cron, startup), privilege escalation, log clearing, kernel module
- **Windows:** Brute force, privilege use
- **Network:** Nmap scan, reverse shell, lateral movement
- **Malware:** Crypto miner, base64 execution, download-execute pattern

---

## Stack Teknologi

| Layer | Teknologi |
|-------|-----------|
| Agent | Go 1.22, statically linked |
| API | Python 3.12, FastAPI, SQLAlchemy async, Alembic |
| Worker | Python 3.12, asyncio, scikit-learn (Isolation Forest) |
| Dashboard | React 18, TypeScript, Vite, TailwindCSS, Zustand, Recharts |
| Database | PostgreSQL 16 |
| Queue | Redis 7 (Stream) |
| Proxy | Nginx |
| Search | SearXNG |
| AI | Groq API |
| Packaging | Docker Compose, .deb, .rpm |

---

## Deployment

```bash
# Production
docker compose -f docker-compose.prod.yml up -d

# Development
docker compose -f docker-compose.dev.yml up -d
```

Environment variables utama di `.env`:
```
DATABASE_URL=postgresql+asyncpg://...
REDIS_URL=redis://redis:6379
SECRET_KEY=...
GROQ_API_KEY=...
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
```

---

## Alur Data Lengkap

```
1. Admin buat enrollment token di dashboard
2. Pasang siem-agent di endpoint, isi enrollment_token di config.yaml
3. Agent POST /api/agent/enroll → dapat agent_id + agent_token
4. Agent tail /var/log/auth.log, /var/log/secure, dll
5. Setiap baris baru → POST /api/ingest/log
6. Server enqueue ke Redis Stream "siem:logs"
7. Worker consume → DecoderEngine parse regex → Event tersimpan ke DB
8. SigmaEngine evaluate → match rule → Alert dibuat → Webhook dikirim
9. UEBA scorer update risk score entity (user/IP)
10. SOC analyst lihat alert di dashboard, buka case, investigasi dengan AI analyst
11. Live response: kirim task ke agent (artifact collection, YARA scan)
```
