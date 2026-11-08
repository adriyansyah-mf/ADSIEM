# Web Protection (Stage B2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Endpoint agents (Linux and Windows) enforce the Web Protection blocklist from B1: hosts-file sinkhole, an auto-generated per-endpoint CA, a local block page server, `web_block` events, health in the heartbeat, clean removal on uninstall; plus the server/dashboard view of agent health.

**Architecture:** New Go package `agent/internal/webblock`. `Store` syncs the list exactly like `malhash` (delta pages, rules marker, group reset) and saves it in `state_dir`. `Controller.Apply(list)` brings the host to the list's state through three narrow interfaces (`Hosts`, `Authority`, `PageServer`) with Linux and Windows implementations behind build tags. Heartbeat carries `web_block_health`; the server stores it per agent and lists it on the Web Protection page.

**Tech Stack:** Go 1.25 (`crypto/x509`, `crypto/ecdsa`, `crypto/tls`, `net/http`, `golang.org/x/sys/windows`), Python/FastAPI, React + TS.

**Spec:** `docs/superpowers/specs/2026-11-07-threat-iocs-web-protection-design.md` (section B2, plus the B1 "Agent sync endpoint" contract)

## Global Constraints

- Linux and Windows ship together at the same level (platform parity rule). Every OS-specific file has a sibling for the other OS (or `_other.go` no-op for unsupported OSes) and the package builds with `GOOS=linux`, `GOOS=windows`, `GOOS=darwin`.
- Sync contract (server, B1): `POST /api/ingest/web-blocklist {since, continuing, rules}` → `{group, seq, reset, more, rules, version, policy:{enabled, page_html, contact, max_entries}, changes:[{domain, action:"block", source, reason} | {domain, action:"remove"}]}`. Heartbeat `web_blocklist_version`: `""` = off, otherwise opaque `"<group>:<seq>[+]"`. Store `rules` from the first page and every `reset` page and echo it on `continuing` pages. Save `version` only from the final page. Reset local state when `group` differs from the stored group. Compare versions as opaque strings.
- Off (`""` or `policy.enabled=false`): remove the hosts block, stop the page server, remove the CA from the trust store and delete its key.
- Hosts block markers: `# BEGIN ADSIEM WEBBLOCK` / `# END ADSIEM WEBBLOCK`; lines outside are never changed; written via temp file in the same directory + rename (Windows: retry on sharing violation, 5 × 200 ms). Each domain and `www.<domain>` → `127.84.0.1`, and `::1` only while the `[::1]` page listeners are up.
- At most `max_entries` domains, priority manual > alert > urlhaus/phishtank, then domain name for determinism.
- CA: ECDSA P-256, subject CN `ADSIEM Web Protection (<hostname>)`, O `ADSIEM`, 10 years, `IsCA`, `MaxPathLenZero`, KeyUsage CertSign|CRLSign. Key file `state_dir/webblock-ca.key` (PEM, 0600 root on Linux; DACL SYSTEM + Administrators full control, protected, on Windows). Cert `state_dir/webblock-ca.crt`.
- Leaf certs minted per SNI only for listed domains (or `www.` of one); 7-day validity, ECDSA P-256, in-memory LRU of 1024.
- Page server: `127.84.0.1:80`, `127.84.0.1:443`, `[::1]:80`, `[::1]:443`. Every request → `403` with the rendered page; headers `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Type: text/html; charset=utf-8`. A failed bind does not stop the others; health reports `page_server: "page_unavailable"` with the address.
- Template variables `{{domain}} {{reason}} {{source}} {{time}} {{hostname}} {{contact}}` (optional spaces inside braces) HTML-escaped like Python `html.escape(quote=True)`; unknown placeholders left as is. Page wrapped like `web_page.document()`.
- Events: log type `web_block`, kv line `event=web_block action=blocked domain=… scheme=http|https path=… source=… reason="…"` plus ` process="…" pid=N` when known and ` count=N` when >1. Rate limit: one line per (domain, pid) per minute, counting suppressed hits. Urgent log type.
- Health JSON (`web_block_health` in the heartbeat request): `{enabled, entries, version, group, ca_installed, ca_fingerprint, page_server, hosts_tampered, last_error}`.
- Removal: flag `-webblock-cleanup -config <path>` removes the hosts block, the CA from the trust store, the key/cert files and the saved list; packaging removal calls it (deb prerm, rpm %preun, MSI deferred custom action as SYSTEM).
- Server side: read `alerts:read`; group-scoped; CI pins pytest-asyncio 0.24.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Test commands

```bash
cd agent && go test ./internal/webblock/... && GOOS=windows go vet ./internal/webblock/... && GOOS=darwin go vet ./internal/webblock/...
cd agent && go build ./... && GOOS=windows go build ./...
# server (Postgres as in B1)
export JWT_SECRET=ci-test-secret-0123456789abcdef0123456789abcdef TEST_DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test
/tmp/adsiem-ci-venv/bin/python -m pytest tests/server-api -q -p no:cacheprovider
# Linux end to end (root)
cd agent && sudo -E env "PATH=$PATH" WEBBLOCK_E2E=1 go test -count=1 -run E2E -v ./internal/webblock/
```

## File Structure (`agent/internal/webblock/`)

| File | Responsibility |
|---|---|
| `list.go` | `List`, `Entry`, `Policy`; apply a page; `Selected()` (priority + cap); JSON save/load |
| `store.go` | `Store`: `Open`, `Current`, `Want`, `SyncLoop`, `Sync` (like malhash) |
| `hosts.go` | render/replace the managed block; `HostsFile` implementation of `Hosts` |
| `hosts_linux.go`, `hosts_windows.go`, `hosts_other.go` | hosts path, atomic replace, DNS cache flush |
| `ca.go` | `CA` generate/load/save, `Mint(sni)` with allowlist + LRU, fingerprint |
| `trust_linux.go`, `trust_windows.go`, `trust_other.go` | install/remove the CA in the system trust store; key file protection |
| `page.go` | render template, `document()`, HTTP handler with headers |
| `server.go` | listeners (80/443 × v4/v6), TLS config, start/stop, bind status |
| `event.go` | event line + rate limiter |
| `owner_linux.go`, `owner_windows.go`, `owner_other.go` | best-effort client PID + process name for a local TCP port |
| `controller.go` | `Controller.Apply(list)`, `Health()`, `Cleanup()` |
| `e2e_test.go` | `WEBBLOCK_E2E=1` end-to-end (Linux root; Windows admin on CI) |

Elsewhere: `agent/internal/heartbeat/heartbeat.go` (request/response fields), `agent/cmd/agent/main.go` (wiring, flag), `agent/packaging/build-deb.sh`, `agent/packaging/siem-agent.spec`, `agent/packaging/windows/siem-agent.wxs`, `decoders/web_block.yaml`, server-api (heartbeat schema, agents column, `GET /api/web-blocks/agents`), dashboard (Agents tab), `.github/workflows/ci.yml` and `windows-agent.yml`, `docs/operations/web-protection.md`.

---

### Task 1: List model and delta sync store

**Files:** Create `agent/internal/webblock/list.go`, `agent/internal/webblock/store.go`, tests `list_test.go`, `store_test.go`.

**Interfaces (produced):**
```go
const Path = "/api/ingest/web-blocklist"
const ListFile = "webblock.json"
type Policy struct { Enabled bool `json:"enabled"`; PageHTML string `json:"page_html"`; Contact string `json:"contact"`; MaxEntries int `json:"max_entries"` }
type Entry struct { Source string `json:"source"`; Reason string `json:"reason"` }
type List struct { Version, Group string; Seq, Rules int64; Policy Policy; Entries map[string]Entry }  // json tags snake_case
func Empty() *List
func (l *List) Active() bool                      // Version != "" && Policy.Enabled
func (l *List) Selected() []string                 // ≤ MaxEntries (0 → 50000), priority manual>alert>others, then name
func (l *List) Save(path string) error; func Load(path string) (*List, error)
type Poster interface { PostContext(ctx context.Context, path string, payload any) (*http.Response, error) }
type Store struct { OnChange func(*List) /* … */ }
func Open(path string) *Store; func (s *Store) Current() *List; func (s *Store) Want(version string)
func (s *Store) SyncLoop(ctx context.Context, c Poster); func (s *Store) Sync(ctx context.Context, c Poster, want string) error
```

Behaviour (copy `internal/malhash/sync.go` structure: retry every minute, wake channel, 5-minute timeout, max 500 pages, 64 MiB response limit):

- `Sync(want "")` installs `Empty()` (unless already empty) — the controller then turns everything off.
- Otherwise: `since = cur.Seq`, `rules = cur.Rules`; if the first page's `group != cur.Group`, restart once from `since=0` with a fresh list. Each page: if `reset`, start from an empty entry map and set `rules = page.Rules` (also on continuing pages); apply changes (`block` sets the entry, `remove` deletes it); continue with `since = page.Seq`, `continuing = true`, echoing `rules`, while `more`. On the final page set `Version = page.Version`, `Seq`, `Rules`, `Group`, `Policy`. A page with `policy.enabled == false` installs `Empty()`.
- `install` saves (warn on error, still enforce), stores, calls `OnChange`.
- `wanted()` needs a sync when `want != Current().Version`.

Tests (fake Poster returning queued pages; record request bodies):
1. first sync: reset page with 3 blocks → entries 3, version/seq/rules/group stored, request `{since:0, continuing:false, rules:0}`.
2. delta: block + remove applied on top of saved state.
3. paging: two pages, second request has `continuing:true`, `since` = page-1 seq, `rules` = page-1 rules; version only from the last page.
4. reset arriving on a continuing page drops earlier entries and adopts the new rules for the next page.
5. group change: stored group "blue", server answers group "red" → second request has `since:0`, final entries only from red.
6. `want == ""` → `Empty()` installed and `OnChange` called; `policy.enabled == false` page → `Empty()`.
7. `Selected()` cap and priority: 5 entries (2 manual, 1 alert, 2 urlhaus) with MaxEntries 3 → both manual + the alert; ties sorted by name; MaxEntries 0 → 50000.
8. Save/Load round trip; Load of a missing file → error and `Open` falls back to `Empty()`.

Commit: `feat(webblock): blocklist model and delta sync store`.

---

### Task 2: Hosts file sinkhole

**Files:** Create `hosts.go`, `hosts_linux.go`, `hosts_windows.go`, `hosts_other.go`, test `hosts_test.go`.

**Interfaces:**
```go
const BlockBegin = "# BEGIN ADSIEM WEBBLOCK"; const BlockEnd = "# END ADSIEM WEBBLOCK"
const SinkV4 = "127.84.0.1"; const SinkV6 = "::1"
func RenderBlock(domains []string, ipv6 bool) string          // markers + "127.84.0.1 d" + "127.84.0.1 www.d" (+ ::1 lines); "" when no domains
func ReplaceBlock(content, block string) (out string, hadBlock bool, tampered bool)
type Hosts interface { Apply(domains []string, ipv6 bool) (tampered bool, err error); Remove() error }
type HostsFile struct { Path string; Flush func() error }  // implements Hosts
func NewHostsFile() *HostsFile                                // OS default path + flush
```

- `ReplaceBlock` keeps every line outside the markers byte-for-byte (including the file's line endings: detect `\r\n`), removes an existing block (first BEGIN to the next END), appends the new block at the end preceded by one newline. `tampered` = a BEGIN without END, or more than one block. An empty `block` removes the block.
- `HostsFile.Apply` reads the file (missing → error), computes the new content; if unchanged returns without writing; otherwise writes `path+".adsiem.tmp"` with the original file mode, `fsync`, renames over the original (`os.Rename`; Windows: retry 5× 200 ms on `ERROR_SHARING_VIOLATION`/`ERROR_ACCESS_DENIED`), then calls `Flush` (errors from Flush are logged, not returned). `www.` is not added for a domain that already starts with `www.`.
- Linux path `/etc/hosts`; flush: run `resolvectl flush-caches` if `resolvectl` exists and `systemctl is-active --quiet systemd-resolved` succeeds, and `nscd -i hosts` if `nscd` exists (ignore missing tools). Windows path `%SystemRoot%\System32\drivers\etc\hosts` (`os.Getenv("SystemRoot")`, default `C:\Windows`); flush via `dnsapi.dll` `DnsFlushResolverCache` (`windows.NewLazySystemDLL`). Other OSes: path `/etc/hosts`, flush no-op.

Tests (temp files only): foreign lines preserved byte-for-byte (LF and CRLF files); idempotent second Apply does not rewrite (mtime unchanged); domains rendered with `www.`; ipv6 lines only when asked; removal leaves the file identical to the original; tampered detection for BEGIN-without-END and two blocks (both repaired to a single block); Flush called once per real write.

Commit: `feat(webblock): managed hosts file block`.

---

### Task 3: Local CA, leaf minting and trust store

**Files:** Create `ca.go`, `trust_linux.go`, `trust_windows.go`, `trust_other.go`, test `ca_test.go`.

**Interfaces:**
```go
const CAKeyFile = "webblock-ca.key"; const CACertFile = "webblock-ca.crt"
type CA struct { Cert *x509.Certificate; Key *ecdsa.PrivateKey; DER []byte /* … */ }
func LoadOrCreateCA(dir, hostname string) (ca *CA, created bool, err error) // regenerate when files missing/corrupt/mismatched/expiring within 30 days
func (c *CA) Fingerprint() string                                            // hex SHA-256 of DER, lowercase
func (c *CA) SetAllowed(allowed func(host string) bool)
func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) // error for empty/unlisted SNI
type Authority interface { Ensure(hostname string) (fingerprint string, err error); Remove() error; Installed() bool }
type TrustStore struct { Dir string /* state dir */ }                       // implements Authority via OS install/remove
func installTrust(der []byte, fingerprint string) error                       // per OS
func removeTrust(fingerprint string) error                                     // per OS; removes every ADSIEM Web Protection cert it finds
func protectKeyFile(path string) error                                         // per OS
```

- Generation per Global Constraints; serial 128-bit random; NotBefore now−1h. Leaf: CN = SNI, DNSNames = [SNI], ExtKeyUsage ServerAuth, NotBefore now−1h, NotAfter now+7d, signed by the CA; cached per SNI until 24 h before expiry (LRU 1024).
- `TrustStore.Ensure`: `LoadOrCreateCA`; if created or not installed, `removeTrust` old ADSIEM certs then `installTrust`; returns the fingerprint. `Remove`: `removeTrust`, delete key and cert files.
- Linux: if `update-ca-certificates` is on PATH → write `/usr/local/share/ca-certificates/adsiem-webblock.crt` (PEM, 0644) and run it; else if `update-ca-trust` → `/etc/pki/ca-trust/source/anchors/adsiem-webblock.crt` and run `update-ca-trust extract`; else error `no supported trust store tool`. Remove deletes the file(s) and re-runs the tool. Key file 0600 (`os.Chmod`) and owned by the process user.
- Windows: `windows.CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, "ROOT")`, `CertCreateCertificateContext`, `CertAddCertificateContextToStore(…, CERT_STORE_ADD_REPLACE_EXISTING, …)`; removal enumerates with `CertEnumCertificatesInStore` and deletes contexts whose subject CN starts with `ADSIEM Web Protection` (`CertDeleteCertificateFromStore` on a duplicated context). Key file DACL via `windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")` + `windows.SetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION, …)`.
- Other OSes: install/remove return `errors.ErrUnsupported`.

Tests (no trust store): generated CA has IsCA, MaxPathLenZero, CertSign, 10-year validity, ECDSA P-256; reload returns the same fingerprint and `created=false`; corrupt key file → regenerated; leaf for an allowed SNI verifies against a pool containing only the CA for that DNS name; `www.` of an allowed domain is minted when `allowed` says so; unlisted or empty SNI → error; second mint returns the cached leaf; Linux key file mode 0600 (skip on Windows).

Commit: `feat(webblock): per-endpoint CA, leaf minting and trust store`.

---

### Task 4: Block page server and events

**Files:** Create `page.go`, `server.go`, `event.go`, `owner_linux.go`, `owner_windows.go`, `owner_other.go`, `decoders/web_block.yaml`; tests `page_test.go`, `event_test.go`, `server_test.go`.

**Interfaces:**
```go
const LogType = "web_block"
func Render(page string, values map[string]string) string     // escape like html.escape(quote=True): & < > " '
func Document(page string, values map[string]string) string    // same wrapper as server-api web_page.document()
type Lookup func(host string) (Entry, bool)                     // listed entry for a host (www. falls back to the apex)
type PageServer interface { Start(page, contact string, lookup Lookup, ca *CA) (ipv6 bool, status string); Stop() }
type Server struct { Push func(logType, line string); Hostname string /* … */ }  // implements PageServer
type Event struct { Domain, Scheme, Path, Source, Reason, Process string; PID int; Count int }
func (e Event) Line() string
type Limiter struct{ /* per (domain,pid) per minute */ }
func (l *Limiter) Allow(domain string, pid int, now time.Time) (emit bool, suppressed int)
func clientProcess(remoteAddr string) (pid int, name string)    // per OS, best effort; (0,"") when unknown
```

- `Render`/`Document` must produce byte-identical output to the Python `render`/`document` for the same input: add a table test with these vectors (copy expected strings from `server-api/app/services/web_page.py` behaviour): `"<p>{{ domain }}</p>{{other}}"` with domain `<b>x</b>` → `"<p>&lt;b&gt;x&lt;/b&gt;</p>{{other}}"`; `"'"` and `"\""` escaped to `&#x27;` and `&quot;`.
- Handler: any method/path → 403 with `Document(page, values)` where values = domain (the requested host, lowercased, no port), reason/source from `lookup` (fallback "Blocked by your organisation" / "policy"), time (UTC `2006-01-02 15:04 UTC`), hostname, contact; headers per Global Constraints. HEAD gets headers only. After writing, emit an event through the limiter (process via `clientProcess(r.RemoteAddr)`; scheme from `r.TLS != nil`; path = `r.URL.Path` for HTTP, `""` for HTTPS? — record `r.URL.Path` in both cases; it is visible to the local server after TLS termination).
- `Start` binds the four listeners independently (`net.Listen("tcp", addr)`), HTTPS via `tls.NewListener` with `GetCertificate: ca.GetCertificate`, `MinVersion: tls.VersionTLS12`. Returns `ipv6 = both [::1] listeners up` and `status = "ok"` or `"page_unavailable: <addr>, …"` listing failed binds. `Stop` closes listeners and servers (idempotent). `Start` on a running server swaps page/contact/lookup without rebinding.
- `owner_linux.go`: parse `/proc/net/tcp` and `/proc/net/tcp6` for a socket whose local port equals the client's port and remote equals the server address → inode; scan `/proc/[0-9]*/fd/*` symlinks for `socket:[inode]` → pid; name from `/proc/pid/comm`. `owner_windows.go`: `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` (IPv4; IPv6 with AF_INET6) → row with local port == client port → pid; name via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageName` (base name). Reuse the parsing approach of `internal/hygiene/collector*.go` without importing it (keep packages independent). Any error → `(0, "")`.
- `decoders/web_block.yaml` (copy the structure of `decoders/known_malware.yaml`): name/log_type `web_block`, type kv, match `'event=web_block '`, fields `web.action: action`, `url.domain: domain`, `url.scheme: scheme`, `url.path: path`, `web.block_source: source`, `web.block_reason: reason`, `process.name: process`, `process.pid: pid`, `event.count: count`; static_fields `event.category: network`, `event.action: web_block`.

Tests: render vectors; handler returns 403 + all headers + escaped values for a listed host and the fallback for an unknown host; HEAD has no body; limiter emits once per minute per (domain,pid) and reports the suppressed count on the next emit; event line quoting (quotes/newlines escaped like malhash `kv`); server test on high ports: make the listen addresses injectable (`Server.Addrs` defaulting to the four constants) and start on `127.0.0.1:0`-style ports to fetch a page over HTTP and HTTPS (client trusting only the CA, SNI `evil.example`), and assert an unlisted SNI fails the handshake; `Start` with an occupied port reports `page_unavailable` and keeps the others.

Commit: `feat(webblock): block page server and web_block events`.

---

### Task 5: Controller, agent wiring and removal

**Files:** Create `controller.go`, `controller_test.go`; modify `agent/internal/heartbeat/heartbeat.go`, `agent/cmd/agent/main.go`, `agent/packaging/build-deb.sh`, `agent/packaging/siem-agent.spec`, `agent/packaging/windows/siem-agent.wxs`.

**Interfaces:**
```go
type Health struct {
  Enabled bool `json:"enabled"`; Entries int `json:"entries"`; Version string `json:"version"`; Group string `json:"group"`
  CAInstalled bool `json:"ca_installed"`; CAFingerprint string `json:"ca_fingerprint"`; PageServer string `json:"page_server"`
  HostsTampered bool `json:"hosts_tampered"`; LastError string `json:"last_error"`
}
type Controller struct { Hosts Hosts; Authority Authority; Server PageServer; Hostname string /* … */ }
func (c *Controller) Apply(l *List)          // serialised; never panics; records LastError
func (c *Controller) Health() Health
func Cleanup(stateDir string) error           // hosts block, trust store, key/cert files, saved list
```

- `Apply(active list)`: `Authority.Ensure` (error → LastError, continue without HTTPS: page server still serves HTTP); `Server.Start(page, contact, lookup, ca)` → ipv6/status; `Hosts.Apply(list.Selected(), ipv6)` → tampered. `Apply(inactive)`: `Hosts.Remove`, `Server.Stop`, `Authority.Remove`. Health reflects the last Apply. The CA's allowed set = the selected domains (+ `www.`).
- A periodic re-apply every 5 minutes repairs a tampered/removed hosts block (`Controller.Run(ctx, store)`): re-apply `store.Current()`.
- Heartbeat: `HeartbeatResponse.WebBlocklistVersion string json:"web_blocklist_version"`; `HeartbeatRequest.WebBlockHealth any json:"web_block_health,omitempty"` filled from a callback the agent sets (follow how `EvidenceHealth` is filled).
- main.go: open the store at `filepath.Join(task.StateDir(cfg), webblock.ListFile)`, build the controller with `NewHostsFile()`, `&TrustStore{Dir: stateDir}`, `&Server{Push: push, Hostname: hostname}`; `store.OnChange = controller.Apply`; apply the loaded list at start; `go store.SyncLoop(flowCtx, c)`; `go controller.Run(flowCtx, store)`; in the heartbeat callback `store.Want(resp.WebBlocklistVersion)`; add `webblock.LogType` to `urgentLogTypes`. Flag `-webblock-cleanup` (with `-config`): load config for the state dir, run `webblock.Cleanup`, exit 0 (log errors, exit 1 only if the hosts block could not be removed).
- Packaging: deb prerm and rpm `%preun` (removal, not upgrade — inside the same branch that runs `-verify-uninstall`, after it succeeds) run `/usr/bin/siem-agent -webblock-cleanup -config /etc/siem-agent/config.yaml || true`. MSI: a `CustomAction Id="WebBlockCleanup" FileRef="AgentExe" Execute="deferred" Impersonate="no" Return="ignore"` with `ExeCommand="-webblock-cleanup -config &quot;[CommonAppDataFolder]SIEMAgent\config.yaml&quot;"`, scheduled `Before="RemoveFiles"` with condition `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE`.

Tests (fakes for the three interfaces): active list → Ensure, Start, Hosts.Apply with Selected() and the ipv6 flag from Start; inactive → Remove, Stop, Remove (in that order); Ensure error → LastError set and hosts still applied; Hosts tampered → Health.HostsTampered; Cleanup on a temp state dir with a fake hosts path (make Cleanup take its dependencies through a small internal function so it is testable).

Commit: `feat(webblock): controller, agent wiring and clean removal`.

---

### Task 6: Server and dashboard: agent health

**Files:** `server-api/app/schemas/schemas.py` (`HeartbeatRequest.web_block_health`), `server-api/app/models/models.py` (`Agent.web_block_health` JSONB, `web_block_health_at`), `server-api/app/main.py` (`_migrate_agent_web_block_health`: `ALTER TABLE agents ADD COLUMN IF NOT EXISTS …` inside the lock), `server-api/app/api/routes/ingest.py` (store on heartbeat), `server-api/app/api/routes/web_protection.py` (`GET /api/web-blocks/agents`), dashboard hook + "Agents" tab, tests.

- Schema `WebBlockHealth` (pydantic, all fields optional with defaults; extra ignored; strings capped at 300 chars) — an invalid payload is dropped like `evidence_health`.
- `GET /api/web-blocks/agents` (`alerts:read`, group-scoped like the agents list): `{"items":[{agent_id, hostname, group_id, online, health, health_at}]}` for approved agents, ordered by hostname; `online` = existing agent status field.
- Dashboard: Web Protection page gets an "Agents" tab: table hostname, group (superadmin), status (enabled/off), entries, CA installed + short fingerprint, page server status (red when `page_unavailable`), hosts tampered, last error, last report time.
- Tests: heartbeat with valid health stores it; invalid health ignored; endpoint scoped (red agent hidden from blue analyst); tsc + vite build.

Commit: `feat(webblock): agent web protection health in the API and dashboard`.

---

### Task 7: End-to-end tests, CI and operations doc

**Files:** `agent/internal/webblock/e2e_test.go`, `.github/workflows/ci.yml`, `.github/workflows/windows-agent.yml`, `docs/operations/web-protection.md`.

- `TestWebBlockE2E` (skip unless `WEBBLOCK_E2E=1`; needs root/admin): build a Controller with the real `HostsFile`, `TrustStore` and `Server`; Apply a list blocking `adsiem-e2e-blocked.example`; assert `net.DefaultResolver.LookupHost` returns `127.84.0.1`; `http.Get("http://adsiem-e2e-blocked.example/x")` → 403 with the domain in the body; an HTTPS GET using `x509.SystemCertPool()` (Linux: system store; Windows: Go uses the system verifier) → 403; a `web_block` line was pushed; Apply an inactive list → lookup no longer returns 127.84.0.1, the CA is gone from the store (Linux: file removed; Windows: no ADSIEM cert in ROOT), key file removed, hosts file equals its original bytes. Always restore the original hosts file in `t.Cleanup`.
- CI: in `ci.yml` go-tests job add a step after the linsensor e2e: `sudo -E env "PATH=$PATH" WEBBLOCK_E2E=1 go test -count=1 -run E2E -v ./internal/webblock/` (working-directory agent). In `windows-agent.yml` add a job (or a step in the existing Go test job) on `windows-latest`: `go test ./agent/internal/webblock/... -count=1` and `$env:WEBBLOCK_E2E='1'; go test ./agent/internal/webblock -run E2E -count=1 -v`.
- `docs/operations/web-protection.md`: what it does; turning it on per group; the per-endpoint CA (where the key lives, why its risk is low, how removal cleans up); browser notes (Windows Chrome/Edge show the page; Firefox needs `ImportEnterpriseRoots`; Linux desktop browsers show a certificate error but stay blocked; DoH recommendation); troubleshooting (`page_unavailable`, `hosts_tampered`, flush DNS); the `-webblock-cleanup` flag.

Commit: `test(webblock): end-to-end on Linux and Windows CI; operations doc`.

## Final verification

```bash
cd agent && go test ./... && GOOS=windows go build ./... && GOOS=darwin go build ./...
cd agent && sudo -E env "PATH=$PATH" WEBBLOCK_E2E=1 go test -count=1 -run E2E -v ./internal/webblock/
/tmp/adsiem-ci-venv/bin/python -m pytest tests/server-api tests/evidence -q -p no:cacheprovider
cd dashboard && npx tsc --noEmit -p . && npx vite build
```
