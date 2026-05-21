# FULL PROMPT — Build Full Dockerized SIEM Platform

Saya ingin membuat platform SIEM modern seperti Wazuh tetapi lebih modular dan sederhana untuk dikembangkan.

Tolong buatkan FULL SOURCE CODE project dari awal sampai bisa dijalankan end-to-end menggunakan Docker Compose.

Project harus production-oriented, modular, expandable, dan semua kode harus nyata (bukan pseudo-code).

====================================================================
TUJUAN PROJECT
==============

Platform SIEM terdiri dari:

* Agent
* Server API
* Worker / Detection Engine
* Dashboard
* Database
* Message Queue

Flow utama:

Agent membaca log dari endpoint
→ Agent mengirim log ke server
→ Server memasukkan log ke queue
→ Worker memproses log
→ Decoder melakukan parsing log
→ Sigma engine melakukan rule matching
→ Jika match maka alert dibuat
→ Dashboard menampilkan logs dan alerts

====================================================================
CORE FEATURES
=============

Wajib ada:

1. Agent-based architecture
2. Log collection
3. Custom decoders
4. Sigma-based rule engine
5. Alert generation
6. RBAC
7. Dashboard web
8. Dockerized deployment
9. Multi-agent support
10. API-first architecture
11. Audit logging
12. Health monitoring

====================================================================
TECH STACK
==========

Gunakan:

* Agent:

  * Golang

* API:

  * Python FastAPI

* Worker:

  * Python

* Dashboard:

  * React + Vite

* Database:

  * PostgreSQL

* Queue:

  * NATS

* Containerization:

  * Docker + Docker Compose

====================================================================
AGENT REQUIREMENTS
==================

Agent ditulis menggunakan Golang.

Fitur wajib:

* Membaca multiple log source:

  * /host/var/log/auth.log
  * /host/var/log/syslog
  * /host/var/log/secure
  * custom log path

* Realtime log tailing

* Config menggunakan YAML

* Heartbeat ke server

* Buffer jika server down

* Retry queue sederhana

* Multiple log source support

* Structured JSON payload

* Enrollment token

* Agent token

* Agent group

* Agent version

* Agent hostname

* Agent status online/offline

* Graceful reconnect

* Logging internal agent

Config contoh:

```yaml
agent:
  id: agent-001
  name: webserver-prod
  group: production
  token: CHANGE_ME

server:
  url: http://server-api:8080

logs:
  - path: /host/var/log/auth.log
    type: linux_auth

  - path: /host/var/log/nginx/access.log
    type: nginx_access
```

Agent endpoint:

* POST /api/ingest/log
* POST /api/ingest/heartbeat
* POST /api/agent/enroll

====================================================================
SERVER API REQUIREMENTS
=======================

Gunakan FastAPI.

Fitur:

* JWT authentication
* Refresh token
* RBAC
* Agent auth token
* REST API
* Audit logging
* Healthcheck endpoint
* Metrics endpoint

Endpoint wajib:

AUTH

* POST /api/auth/login
* POST /api/auth/refresh
* GET /api/auth/me

AGENTS

* GET /api/agents
* POST /api/agent/enroll
* PUT /api/agents/{id}
* DELETE /api/agents/{id}

LOGS

* GET /api/logs

EVENTS

* GET /api/events

ALERTS

* GET /api/alerts
* PUT /api/alerts/{id}
* POST /api/alerts/{id}/notes

RULES

* GET /api/rules
* POST /api/rules
* PUT /api/rules/{id}
* DELETE /api/rules/{id}
* POST /api/rules/test

DECODERS

* GET /api/decoders
* POST /api/decoders
* PUT /api/decoders/{id}
* DELETE /api/decoders/{id}
* POST /api/decoders/test

USERS

* GET /api/users
* POST /api/users
* PUT /api/users/{id}
* DELETE /api/users/{id}

SYSTEM

* GET /health
* GET /metrics

====================================================================
RBAC REQUIREMENTS
=================

Roles:

* superadmin
* admin
* analyst
* viewer

Permission model:

* users:manage
* rules:create
* rules:update
* rules:delete
* decoders:create
* decoders:update
* decoders:delete
* logs:read
* alerts:read
* alerts:update
* agents:manage

Behavior:

* superadmin:
  full access

* admin:
  manage agents/rules/decoders

* analyst:
  read logs/alerts + update alert status

* viewer:
  read-only

Implement:

* permission guard
* dependency-based auth middleware
* JWT access token
* JWT refresh token
* bcrypt password hashing
* protected API routes

Default user:

* username: admin
* password: admin123
* role: superadmin

Development only warning wajib ada di README.

====================================================================
MULTI GROUP / MULTI TENANT
==========================

Support:

* agent group
* user group restriction

Contoh:

* user analyst-finance hanya bisa melihat:

  * agent finance
  * logs finance
  * alerts finance

Superadmin bisa lihat semua.

====================================================================
WORKER REQUIREMENTS
===================

Worker menggunakan Python.

Flow:

* consume event dari NATS
* load decoders
* parse raw log
* normalize fields
* Sigma matching
* generate alerts
* save to database

Worker wajib support:

* auto reload rules
* auto reload decoders
* parsing failure handling
* logging
* metrics
* healthcheck

====================================================================
DECODER ENGINE
==============

Format decoder YAML.

Contoh:

```yaml
name: linux_auth_failed
type: regex

pattern: 'Failed password for (?P<user>\S+) from (?P<src_ip>\S+)'

fields:
  event.category: authentication
  event.action: login_failed
  source.ip: src_ip
  user.name: user
```

Support:

* regex decoder
* priority
* enabled/disabled
* validation
* test decoder endpoint

====================================================================
SIGMA ENGINE
============

Gunakan Sigma YAML style.

Support:

* detection.selection
* condition
* exact match
* contains
* startswith
* endswith
* list matching

Contoh:

```yaml
title: SSH Failed Login

logsource:
  product: linux

detection:
  selection:
    event.action: login_failed

  condition: selection

level: medium
```

Fitur:

* rule validation
* rule enable/disable
* rule tags
* MITRE ATT&CK tags
* rule version
* test rule endpoint
* threshold rule sederhana
* suppression window sederhana

====================================================================
ALERT SYSTEM
============

Alert fields:

* id
* title
* severity
* status
* source.ip
* hostname
* rule_id
* timestamp
* assignee
* notes

Status:

* new
* in_progress
* resolved
* false_positive

Support:

* assign alert
* investigation notes
* audit history

====================================================================
DATABASE REQUIREMENTS
=====================

Gunakan PostgreSQL.

Tabel minimal:

* users
* roles
* permissions
* role_permissions
* agents
* raw_logs
* events
* alerts
* alert_notes
* rules
* decoders
* audit_logs

Semua tabel:

* created_at
* updated_at

Buat:

* init.sql
* migration sederhana

====================================================================
AUDIT LOGGING
=============

Audit log wajib untuk:

* login success/fail
* create/update/delete user
* create/update/delete rule
* create/update/delete decoder
* alert update
* agent enroll/revoke

====================================================================
DASHBOARD REQUIREMENTS
======================

Gunakan React + Vite.

Pages:

* Login
* Dashboard Summary
* Agents
* Logs
* Events
* Alerts
* Rules
* Decoders
* Users

Features:

* JWT auth
* Protected routes
* Sidebar menu based on permission
* Table filtering
* Search
* Pagination
* Alert detail modal
* Rule upload
* Decoder upload
* Status badge
* Dark mode sederhana optional

====================================================================
NOTIFICATION
============

Support:

* webhook notification
* email notification placeholder

Webhook payload:

* alert title
* severity
* source.ip
* hostname
* timestamp

====================================================================
OBSERVABILITY
=============

Tambahkan:

* /health endpoint
* /metrics endpoint
* Prometheus metrics sederhana
* structured logging
* Docker healthcheck

====================================================================
DOCKER REQUIREMENTS
===================

Semua service wajib dockerized.

Service:

* postgres
* nats
* server-api
* worker
* dashboard
* nginx
* agent-demo

Buat:

* Dockerfile semua service
* docker-compose.yml
* docker-compose.dev.yml
* docker-compose.prod.yml

Gunakan:

* restart unless-stopped
* healthcheck
* environment variables
* shared docker network

====================================================================
NGINX REQUIREMENTS
==================

Gunakan nginx reverse proxy:

* dashboard frontend
* API reverse proxy

Support:

* websocket proxy jika perlu
* gzip
* security headers

====================================================================
PROJECT STRUCTURE
=================

```text
siem-docker/
├── docker-compose.yml
├── docker-compose.dev.yml
├── docker-compose.prod.yml
├── README.md
├── .env.example
├── nginx/
├── db/
├── rules/
├── decoders/
├── agent/
├── server-api/
├── worker/
└── dashboard/
```

====================================================================
SAMPLE DECODERS
===============

Buat decoder:

* Linux SSH failed login
* Linux sudo command
* Nginx access log
* Generic syslog

====================================================================
SAMPLE RULES
============

Buat rules:

* SSH failed login
* Multiple SSH failed login
* Sudo command executed
* Nginx suspicious path
* Access to /.env
* Access to /etc/passwd
* WordPress admin probing

====================================================================
README REQUIREMENTS
===================

README harus sangat lengkap.

Isi:

* architecture overview
* service explanation
* setup
* docker deployment
* production deployment
* agent deployment
* enrollment
* adding rules
* adding decoders
* RBAC explanation
* API examples
* curl examples
* troubleshooting
* roadmap
* security notes

====================================================================
CODING REQUIREMENTS
===================

* Jangan pseudo-code
* Semua file harus nyata
* Semua import harus valid
* Semua dependency harus jelas
* Gunakan .env
* Error handling wajib ada
* Logging jelas
* Kode modular
* Gunakan typing jika memungkinkan
* Gunakan async FastAPI jika cocok
* Jangan hardcode secret

====================================================================
IMPORTANT
=========

Fokus utama:
Pipeline wajib berjalan end-to-end:

agent
→ server-api
→ NATS
→ worker
→ decoder
→ sigma match
→ alert
→ dashboard

====================================================================
SELF REVIEW
===========

Setelah generate project:

* cek docker-compose valid
* cek semua service satu network
* cek semua endpoint sinkron
* cek database schema sinkron dengan ORM
* cek dashboard endpoint cocok
* cek worker dapat membaca volume rules/decoders
* cek JWT flow benar
* cek RBAC benar
* cek healthcheck benar
* cek semua Dockerfile valid
* cek semua environment variables digunakan
* cek README sesuai implementasi

Generate seluruh project file-by-file lengkap dengan path file.
Jika output terlalu panjang, lanjutkan sampai semua file selesai.
