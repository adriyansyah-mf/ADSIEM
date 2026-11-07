# Threat IoCs and Web Protection: design

Date: 2026-11-07
Status: approved in brainstorming, awaiting spec review

## Goal

1. **Threat IoCs**: one place to see every attacker indicator (IP, domain, URL,
   hash, email) recorded in alerts, with counts, hosts and first/last seen.
2. **Web Protection**: block endpoint connections to web domains, with a
   per-group custom block page, fed by URLhaus and PhishTank, auto-block from
   alert IoCs, and manual block/unblock.

Both ship for Linux and Windows at the same level (platform parity rule).

## Decisions

| Topic | Decision |
|---|---|
| IoC storage | Elasticsearch index `alert_iocs` (volume + aggregations); config stays in Postgres |
| Enforcement | Hosts-file DNS sinkhole + per-endpoint local CA + local block page server |
| Granularity | Domain level. Default allow: only listed domains are blocked |
| URL feed entries | Reduced to their host; hosts on the allowlist are not blocked |
| Auto-block sources | URLhaus + PhishTank feeds; malicious domain/URL IoCs from alerts |
| Not in scope | SOAR `block_domain` node, URL path blocking, IP blocking via web lists, macOS |
| Block page | Full HTML/CSS with variables; no script (sanitised on save, CSP at serve) |
| Defaults | Web Protection, feed auto-block and alert auto-block are all **off** per group |

## Delivery order

Each stage is reviewed and merged on its own.

- **A**: `alert_iocs` index, IoC API, Threat IoCs page.
- **B1**: server tables, domain normalisation, allowlist, manual block/unblock,
  policies, block page editor, agent sync endpoint.
- **B2**: agent `webblock` package (Linux and Windows).
- **B3**: URLhaus/PhishTank feeds and alert auto-block.

---

## A. Threat IoCs

### Index `alert_iocs`

One document per (alert, indicator). `_id = sha1(alert_id|type|value)`, so a
re-triage overwrites instead of duplicating.

| Field | Type | Notes |
|---|---|---|
| `alert_id` | keyword | |
| `group_id` | keyword | scoping filter on every query |
| `type` | keyword | `ip`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email` |
| `value` | keyword | normalised (lowercase; domains IDNA/punycode) |
| `ioc_key` | keyword | `type:value`, the aggregation key |
| `severity` | keyword | alert severity |
| `severity_rank` | byte | 1 low … 4 critical, for `max` aggregation |
| `hostname`, `agent_id` | keyword | |
| `rule_title` | keyword | |
| `ai_verdict` | keyword | null until triage sets it |
| `origin` | keyword | `alert` (alert column), `event` (decoded fields), `ti` (TI extraction) |
| `created_at` | date | alert time |

The mapping is created idempotently at worker start, like `ensure_index()` for
`logs` in `worker/worker/es_client.py`.

### Writing

- `alert_manager.create_alert` indexes every new alert's indicators (`origin`
  `alert`/`event`). This must happen there: AI triage only runs for alerts at or
  above `ai_min_severity`.
- After AI triage, `persist_node` rewrites the alert's documents (same ids) with
  TI-extracted indicators (`origin=ti`) and `ai_verdict`.

`alert_iocs.collect` differs from `ioc_keys` in one way: it records domains and
URLs for **all** alert families, not only outbound ones. The existing exclusions
still apply: private/excluded networks and owned domains are dropped.

Documents are written with `bulk_index`. An Elasticsearch failure is logged
(`alert_iocs_index_failed`) and never fails triage or loses the alert.

### Deletion and backfill

- Wherever alerts are deleted (retention in `worker/worker/maintenance.py` and
  any API delete path; the plan lists every call site), their documents are
  removed with `delete_by_query` on `alert_id`.
- One-shot backfill job: reads `alerts.source_ip` and `case_alerts.indicators`
  from Postgres and bulk-indexes them (`origin=alert`). Elasticsearch event
  re-reads are out of scope (too heavy).

### API (`server-api/app/api/routes/iocs.py`, permission `alerts:read`)

- `GET /api/iocs?type=&q=&since=&until=&sort=last_seen|alerts&limit=&offset=`
  - Elasticsearch `terms` aggregation on `ioc_key` (size 1000), sub-aggregations
    `cardinality(alert_id)`, `cardinality(hostname)`, `min/max(created_at)`,
    `max(severity_rank)`, then `bucket_sort` for the page.
  - `q` is a `wildcard` on `value`. `group_id` from `get_scoped_group()` is
    always a filter.
  - Response rows: `type, value, alerts, hosts, first_seen, last_seen,
    max_severity, blocked` (`blocked` filled from `web_block_entries` for the
    page's domains once B1 exists; `null` before).
  - `type_counts` from a `terms` aggregation on `type`.
- `GET /api/iocs/alerts?type=&value=&limit=&offset=` (query parameters: URL values contain `/`): alert ids from
  Elasticsearch, alert rows loaded from Postgres with the group filter.

Limit: the list covers the top 1000 indicators of the chosen window and sort.
Deeper results are reached by filtering or searching.

### Dashboard: menu "Threat IoCs"

- Tabs per type with counts, a table (value, alerts, hosts, first/last seen,
  max severity, status), and a detail panel with the linked alerts.
- Row actions: **Block web** (domain/URL, after B1), **Add to malware hashes**
  (hashes, existing API), **Hunt** (existing hunts).

### Tests

- `collect()`: each origin, exclusions dropped, all families keep domains/URLs,
  deterministic `_id`.
- Query body: group filter always present, sort and pagination, `q`.
- Drill-down: alerts from another group are never returned.
- Backfill: maps source IPs and case indicators.

---

## B1. Server: lists, policies, manual control

### Tables (Postgres, created by `create_all`)

**`web_block_entries`**

| Column | Notes |
|---|---|
| `id` | uuid |
| `domain` | normalised host |
| `group_id` | group, or `*` for feed entries (global) |
| `source` | `manual`, `alert`, `urlhaus`, `phishtank` |
| `status` | `active`, `removed`, `suppressed` |
| `reason` | free text; for `suppressed`, the allowlist match |
| `sample_url` | one URL that produced the entry (feeds/alerts) |
| `alert_id` | for `source=alert` |
| `created_by` | user id for manual entries |
| `created_at`, `updated_at` | |
| `expires_at` | null = never |
| `last_seen_in_feed` | feeds only |
| `seq` | bigint from sequence `web_block_seq`, bumped on every change |

Unique `(group_id, domain, source)`. Index on `seq`.

**`web_allowlist`**: `id, group_id ('*' = all), domain, include_subdomains,
builtin, enabled, created_by, created_at`. Changes bump `web_block_seq` too
(agents re-filter).

**`web_block_policies`**: one row per group; `default` is the fallback.

| Column | Default |
|---|---|
| `group_id` | PK |
| `enabled` | false (master switch: CA install and hosts changes only when true) |
| `feed_enabled` | false |
| `alert_enabled` | false |
| `alert_block_days` | 30 |
| `max_entries` | 50000 |
| `page_html` | built-in template |
| `contact` | '' |
| `updated_at`, `seq` | |

### Domain normalisation (`worker/worker/webblock/domains.py`, shared with the API)

1. Parse host from URL or bare domain; strip port, trailing dot, userinfo.
2. Lowercase; IDNA-encode to punycode; reject labels > 63 or host > 253 chars.
3. IP literals are rejected for web blocking (still kept as IoCs).
4. Allowlist match: exact host, or any parent when `include_subdomains`.
   A match stores the entry as `suppressed` with the matching rule as `reason`.

Built-in allowlist (editable, can be disabled per entry):

- include subdomains: `github.com`, `githubusercontent.com`, `google.com`,
  `googleusercontent.com`, `googleapis.com`, `gstatic.com`, `microsoft.com`,
  `live.com`, `office.com`, `sharepoint.com`, `windows.net`, `dropbox.com`,
  `dropboxusercontent.com`, `discordapp.com`, `discord.com`, `amazonaws.com`,
  `cloudfront.net`, `apple.com`, `icloud.com`, `cloudflare.com`, `akamaized.net`,
  plus the platform's own server domain.
- apex only (user subdomains stay blockable): `weebly.com`, `wixsite.com`,
  `blogspot.com`, `wordpress.com`, `000webhostapp.com`, `netlify.app`,
  `vercel.app`, `pages.dev`, `web.app`, `firebaseapp.com`, `herokuapp.com`.

### Dashboard API (`server-api/app/api/routes/web_protection.py`)

Read: `alerts:read`. Changes: `agents:manage`. Feed keys: `settings:manage`.
Every query is group-scoped; every change is audit-logged.

- `GET /api/web-blocks?q=&source=&status=&limit=&offset=`
- `POST /api/web-blocks {domain|url, reason, expires_at?}` → manual entry for
  the caller's group (superadmin may pass `group_id`). Allowlisted → 409 with
  the matching rule.
- `DELETE /api/web-blocks/{id}` → `status=removed`. For a feed entry, an
  allowlist row for the caller's group is added instead, so the next feed sync
  does not re-block it.
- `POST /api/web-blocks/bulk {action: block|unblock, ids|domains}`
- `GET/POST/PATCH/DELETE /api/web-allowlist`
- `GET/PUT /api/web-block-policies/{group_id}`
- `POST /api/web-block-policies/{group_id}/preview` → rendered page with sample
  variables (for the editor).
- `GET /api/web-blocks/agents` → per-agent status from heartbeats.

### Block page HTML

Variables: `{{domain}}`, `{{reason}}`, `{{source}}`, `{{time}}`, `{{hostname}}`,
`{{contact}}`. Values are HTML-escaped at render time on the agent.

Sanitised on save on the server with `nh3` (new dependency in
`server-api/requirements.txt`; Rust-based allowlist sanitiser): drop `script`,
`iframe`, `object`, `embed`, `form`, `base`, `meta http-equiv`, `link`, all
`on*` attributes, and `javascript:`/`vbscript:` URLs; images only as `data:`.
Limit 256 KB. The agent's CSP (B2) is the second layer.

### Agent sync endpoint

`POST /api/ingest/web-blocklist {since}` (agent-token header `X-Agent-Token`,
like the malware hash sync) returns:

```json
{"seq": 123, "more": false,
 "policy": {"enabled": true, "page_html": "...", "contact": "...", "max_entries": 50000},
 "changes": [{"domain": "evil.example", "action": "block", "source": "urlhaus", "reason": "..."},
             {"domain": "old.example", "action": "remove"}]}
```

- `changes` covers global (`*`) entries and the agent's group, after its group
  allowlist; expired and `suppressed` entries are sent as `remove`.
- Pages of 5000 changes; `more=true` continues.
- `since=0` returns the full active set. The server sends the whole allowed set;
  the agent applies `max_entries` and the manual > alert > feed priority (B2).
- The heartbeat response carries `web_blocklist_version` (latest relevant seq
  including policy seq) so agents only fetch on change.

### Tests

Normalisation table (IDNA, ports, IP rejection, apex vs subdomain allowlist),
manual block 409 on allowlist, feed unblock creates group allowlist, sync delta
(remove propagates, other groups never leak, policy change bumps version),
sanitiser cases, permission and group scoping on every route.

---

## B2. Agent `agent/internal/webblock` (Linux and Windows)

### Sync

Same shape as `malhash`: `Store` saved in `state_dir/webblock.json`, `Want(version)`
from the heartbeat, `SyncLoop` fetches pages. The last good list keeps
enforcing while offline or after restart. When `policy.enabled` is false the
agent removes its hosts block and CA and stops the page server.

### Hosts sinkhole

- Managed block between `# BEGIN ADSIEM WEBBLOCK` and `# END ADSIEM WEBBLOCK`
  in `/etc/hosts` or `%SystemRoot%\System32\drivers\etc\hosts`. Lines outside
  the block are never changed. Written to a temp file in the same directory,
  then renamed (Windows: `MoveFileEx` replace with retry on sharing violation).
- Each domain and `www.<domain>` map to `127.84.0.1` and `::1`.
- At most `max_entries` domains, priority manual > alert > feed (newest first).
- DNS cache flush after each write: Windows `DnsFlushResolverCache`; Linux
  `resolvectl flush-caches` when systemd-resolved runs, `nscd -i hosts` when
  nscd runs.
- If the file is modified externally and the block is gone or altered, the next
  sync tick rewrites it and reports `hosts_tampered` in health.

### Local CA (generated automatically)

- Created on first enable: ECDSA P-256, subject
  `ADSIEM Web Protection (<hostname>)`, 10 years, `CA:TRUE, pathlen:0`,
  key usage `certSign`.
- Private key: `state_dir/webblock-ca.key`, mode 0600 root (Linux); ACL
  SYSTEM + Administrators only (Windows). Never sent to the server.
- Installed into the system trust store:
  - Windows: `LocalMachine\Root` via `CertAddCertificateContextToStore`.
  - Debian/Ubuntu: `/usr/local/share/ca-certificates/adsiem-webblock.crt` +
    `update-ca-certificates`.
  - RHEL family: `/etc/pki/ca-trust/source/anchors/adsiem-webblock.crt` +
    `update-ca-trust`.
- Leaf certificates are minted in memory per SNI, **only for a domain on the
  active list** (or its `www.`); any other SNI fails the handshake. 7-day
  validity, LRU cache.
- Missing/corrupt key: old CA removed from the store, a new one created.
- Disable or uninstall: CA removed from the store, key deleted.
- The CA SHA-256 fingerprint goes in the heartbeat.

Risk note: the key allows MITM of that one endpoint, but reading it needs
root/admin, which already allows MITM. Keys are per endpoint, so one leak does
not affect others.

### Block page server

- Listens on `127.84.0.1:80/443` and `[::1]:80/443`. Port 443 uses the minted
  leaf certificates.
- Any request gets `403` with the rendered policy HTML and headers
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'`,
  `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.
- `{{source}}`/`{{reason}}` come from the list entry for the requested host.
- If a bind fails (port in use), the domain stays blocked (connection refused)
  and health reports `page_unavailable` with the address.

### Telemetry

- Each served block becomes a `web_block` event through the existing ingest:
  domain, URL path (HTTP only; HTTPS gives host only), source, process name and
  PID (best effort from the TCP owner table: `GetExtendedTcpTable` on Windows,
  `/proc/net/tcp*` inode lookup on Linux).
- Rate limit: one event per domain per process per minute, with a count.
- Heartbeat `webblock` health: `enabled, entries, version, ca_installed,
  ca_fingerprint, page_server (ok|page_unavailable), hosts_tampered, last_error`.

### Known limits (documented in `docs/operations/web-protection.md`)

- Windows Chrome/Edge show the custom page. Firefox needs the
  `ImportEnterpriseRoots` policy (or `security.enterprise_roots.enabled`).
- Linux desktop browsers use their own NSS store: the site is blocked but shows
  a certificate error. Tools using the system store (curl, wget) show the page.
- Browser DNS-over-HTTPS usually still reads the hosts file; disabling DoH by
  browser policy is recommended.
- Domain level only; no URL path blocking.

### Tests

- Unit: hosts block rewrite (foreign lines untouched, idempotent, atomic),
  priority and cap, CA/leaf generation (leaf refused for unlisted SNI, chain
  verifies against the CA), template render and escaping, CSP header, sync
  delta and offline restart.
- E2E per OS (privileged, like the existing linsensor/prevent e2e): enable,
  resolve a blocked domain to `127.84.0.1`, HTTPS request with the system trust
  store returns the custom page, unblock restores normal resolution, disable
  removes CA and hosts block.

---

## B3. Feeds and alert auto-block

### Feeds (`worker/worker/webblock/feeds.py`, loop like `malware_feed.py`)

| Feed | Interval | Source | Key setting |
|---|---|---|---|
| URLhaus | 30 min | online URL list (CSV) | `abusech_auth_key`, fallback `malwarebazaar_api_key` |
| PhishTank | 60 min | `online-valid.json` | `phishtank_app_key` |

- No key: the feed is skipped with status `missing_key` (PhishTank keys may be
  hard to obtain; registration has been closed for long periods).
- Each URL → normalised domain → allowlist → upsert `group_id='*'` entry with
  `sample_url`, `last_seen_in_feed=now`.
- Entries not seen in the feed for 24 h → `removed`.
- Feed entries reach a group's agents only when that group's `feed_enabled` is
  true (filtered in the sync endpoint).
- State in Redis `siem:webblock_feed:<name>` (last success, counts, last error),
  shown on the Feeds tab.

### Alert auto-block (triage, after A's IoC write)

A domain/URL indicator is blocked for the alert's group when **all** hold:

1. The group's policy has `enabled` and `alert_enabled`.
2. The alert family is outbound (`case_grouping.OUTBOUND_FAMILIES`), so a
   victim's own domain in an inbound web attack alert is never blocked.
3. Malicious evidence: TI enrichment positive (URLhaus listed, or VirusTotal
   malicious ≥ 3), **or** AI verdict `escalate`/`create_case`.
4. Not allowlisted.

Entry: `source=alert`, `alert_id`, `expires_at = now + alert_block_days`.
An alert note and an audit row record it.

### Tests

Feed parsers on recorded samples (CSV/JSON), missing key, 24 h expiry, global
entries filtered by `feed_enabled`; auto-block matrix (each failing condition
blocks nothing; allowlisted → nothing; expiry set).

---

## Dashboard: menu "Web Protection"

Tabs: **Blocklist** (search, source/status filters, block/unblock, bulk),
**Allowlist**, **Feeds** (status, counts, errors, link to key settings),
**Block Page** (per-group HTML editor, live preview in a `sandbox` iframe with
sample variables, reset to built-in), **Agents** (CA status, entries, page
server health, version), **Hits** (`web_block` events from Elasticsearch).
The policy switches (enabled, feed, alert, days, max entries) sit on the
Blocklist tab header.

## Out of scope

SOAR `block_domain` node; URL path blocking or TLS proxying of allowed paths;
IP blocking from web lists; macOS; managing browser DoH settings; popularity
lists (e.g. Tranco) for the allowlist.
