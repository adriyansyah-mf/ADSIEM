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

## Agentic AI

Platform ini memiliki tiga lapisan kecerdasan AI yang berjalan secara otonom tanpa intervensi manual.

---

### AI SOC L1 Analyst (Auto-triage)

**File:** `worker/worker/ai_analyst.py`, `worker/worker/ai_consumer.py`, `worker/worker/groq_client.py`

Setiap alert yang dibuat oleh Sigma engine secara otomatis dikirim ke antrian AI (`siem:ai_analysis` Redis list). Worker `ai_analysis_loop` mengonsumsi antrian ini dan menjalankan pipeline berikut:

```
Alert masuk ke antrian Redis
  → TI Enrichment (7 provider paralel)
  → Heuristic MITRE mapping dari teks alert
  → Severity escalation otomatis berdasarkan TI risk score
  → LLM (Groq / LLaMA-3.3-70B) analisis sebagai SOC L1
  → Keputusan: buat case atau abaikan
  → Jika case dibuat: simpan reasoning + TI summary + IOC
  → Dispatch webhook notifikasi case baru
```

**Keputusan AI:**
- `should_create_case: true/false` — apakah alert perlu eskalasi ke L2
- `reasoning` — analisis 2-3 kalimat dalam Bahasa Indonesia
- `confidence` — skor keyakinan 0.0–1.0
- `ioc_summary` — source IP, threat type, MITRE technique

**Eskalasi severity otomatis:**
- TI risk ≥ 0.75 → severity naik 2 level (misal `medium` → `critical`)
- TI risk ≥ 0.45 → severity naik 1 level
- Severity akhir disimpan di case

**Case yang dibuat AI:**
- Diberi prefix `[AI]` di judul
- `created_by_ai = true`
- Berisi reasoning LLM, extracted IOCs, TI bullets, MITRE techniques, SearXNG search intel
- Note pertama di-generate otomatis oleh AI

---

### Threat Intelligence Enrichment (Multi-provider)

**File:** `worker/worker/ti/`

Berjalan paralel saat setiap alert dianalisis. Mengekstrak IOC dari teks alert, lalu query semua provider secara concurrent.

**7 Provider TI:**

| Provider | Data yang didapat |
|----------|-------------------|
| **AbuseIPDB** | Confidence score abuse, kategori, total reports |
| **VirusTotal** | Deteksi malicious (IP/domain/hash/URL), vendor count |
| **OTX AlienVault** | Pulses threat intel, reputasi |
| **GreyNoise** | Apakah IP adalah scanner/noise atau targeted |
| **URLhaus** | Apakah URL/domain diketahui sebagai malware host |
| **GeoIP** | Negara asal IP, ASN, organisasi |
| **Whois** | Registrar, usia domain, registrant |

**IOC Extractor:** Parse otomatis IPv4, domain, URL, MD5/SHA1/SHA256 hash dari teks bebas.

**Output:** `EnrichmentSummary` berisi:
- `overall_risk` — skor 0.0–1.0 gabungan semua provider
- `provider_bullets` — daftar temuan per provider
- `triage_hints` — saran triage berdasarkan data TI
- `iocs` — list IOC yang diekstrak beserta tipenya

**SearXNG:** Jika provider TI tidak punya data, enrichment dilengkapi dengan web search melalui SearXNG instance sendiri (tidak bergantung Google/Bing).

---

### Threat Hunting Agent (IoC Hunter)

**File:** `worker/worker/hunter.py`

Analisis retrospektif berbasis IoC. SOC analyst submit IoC dari dashboard → worker membangun timeline historis → LLM menganalisis pola serangan.

**Alur:**
```
Analyst submit IoC (IP / domain / hash / user)
  → Query seluruh Alert + Event historis yang mengandung IoC tersebut
  → Query FIM events (untuk hash IoC)
  → Build timeline kronologis
  → LLM (Groq) analisis timeline sebagai threat hunter
  → Output disimpan ke DB, tampil di halaman Hunts
```

**Output analisis AI:**
```json
{
  "risk_level": "critical|high|medium|low",
  "attack_narrative": "Deskripsi narasi serangan dalam Bahasa Indonesia",
  "mitre_techniques": ["T1190", "T1059", "T1486"],
  "campaign_assessment": "isolated|likely_campaign|confirmed_campaign",
  "kill_chain_phase": "initial_access|execution|lateral_movement|...",
  "recommended_actions": ["Blokir IP X", "Isolasi host Y", ...],
  "confidence": 0.87
}
```

**IoC types yang didukung:** IP address, domain, file hash (MD5/SHA1/SHA256), username.

---

### MITRE ATT&CK Mapping

**File:** `worker/worker/ti/mitre.py`

Heuristic keyword-to-technique mapper yang berjalan pada setiap alert tanpa API call:

| Keyword | Teknik |
|---------|--------|
| failed password, brute force | T1110 — Brute Force |
| powershell, encodedcommand | T1059.001 — PowerShell |
| base64 | T1027 — Obfuscated Files |
| web shell | T1505.003 — Web Shell |
| mimikatz | T1003 — OS Credential Dumping |
| kerberoast | T1558.003 — Kerberoasting |
| sql injection | T1190 — Exploit Public-Facing Application |
| ransomware | T1486 — Data Encrypted for Impact |
| exfiltrat | T1041 — Exfiltration Over C2 |
| nmap, port scan | T1046 — Network Service Discovery |

Hasil digunakan sebagai hint tambahan untuk LLM dan disimpan di field `ioc_data.mitre_techniques` pada case.

---

### Konfigurasi AI

Semua setting AI bisa diubah live dari dashboard (Settings) tanpa restart:

| Setting | Default | Keterangan |
|---------|---------|------------|
| `ai_analyst_enabled` | `true` | Toggle seluruh pipeline AI |
| `groq_api_key` | env var | API key Groq |
| `groq_model` | `llama-3.3-70b-versatile` | Model LLM yang dipakai |
| `virustotal_api_key` | — | VirusTotal API key |
| `abuseipdb_api_key` | — | AbuseIPDB API key |
| `otx_api_key` | — | OTX AlienVault API key |
| `greynoise_api_key` | — | GreyNoise API key |
| `searxng_url` | `http://searxng:8080` | URL SearXNG instance |

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
| AI (LLM) | Groq API, LLaMA-3.3-70B-Versatile |
| AI (Search) | SearXNG (self-hosted) |
| AI (TI) | AbuseIPDB, VirusTotal, OTX, GreyNoise, URLhaus, GeoIP, Whois |
| ML (UEBA) | scikit-learn Isolation Forest |
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
9. Alert otomatis masuk antrian AI (Redis list)
10. AI analyst: TI enrichment 7 provider paralel + LLM triage → buat case jika perlu eskalasi
11. UEBA scorer update risk score entity (user/IP) via Isolation Forest
12. SOC analyst lihat alert/case di dashboard, lihat AI reasoning dan TI summary
13. Analyst submit IoC ke Threat Hunting → AI bangun timeline historis + analisis narasi serangan
14. Live response: kirim task ke agent (artifact collection, YARA scan, isolasi jaringan)
```
