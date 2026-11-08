# Web protection (agent)

Web protection stops endpoints from reaching domains on the server's web
blocklist (manual entries, alert-derived domains, URLhaus and PhishTank). The
agent shows a block page instead of the site and reports each attempt to the
SIEM as a `web_block` event.

## What the agent does

When the group's policy enables it, the agent:

1. Syncs the blocklist from `POST /api/ingest/web-blocklist` and keeps it in
   its state directory.
2. Writes a block between `# BEGIN ADSIEM WEBBLOCK` and `# END ADSIEM WEBBLOCK`
   in the hosts file. Each domain and `www.<domain>` points to `127.84.0.1`,
   and to `::1` while the IPv6 listeners are up. Lines outside the block are
   never changed.
3. Serves the block page on `127.84.0.1:80`, `127.84.0.1:443`, `[::1]:80` and
   `[::1]:443`. Every request gets `403` with the page. HTTPS uses a leaf
   certificate minted for the requested name from the per-endpoint CA.
4. Installs that CA in the system trust store so HTTPS shows the page instead
   of a certificate error.
5. Emits `event=web_block action=blocked domain=... scheme=... path=...
   source=... reason="..."`, with `process` and `pid` when known, at most one
   line per domain and process per minute (`count=N` for the suppressed hits).

Turning the feature off for the group (or deleting the policy) reverses every
step: hosts block removed, page server stopped, CA removed from the trust store,
CA files deleted.

## Turning it on

Enable web protection in the group's web protection policy (Settings, per
group). Agents pick it up on the next heartbeat; `web_blocklist_version` in the
heartbeat is empty while off. The agent's Web Protection health (enabled,
entries, version, CA installed, page server, hosts tampered, last error) shows
in the agent detail view and the API.

## The per-endpoint CA

* Generated on the endpoint (ECDSA P-256, 10 years, subject
  `ADSIEM Web Protection (<hostname>)`). No two endpoints share a key and the
  server never sees it.
* Key: `<state_dir>/webblock/` (`webblock-ca.key`), mode 0600 root on Linux;
  SYSTEM and Administrators only on Windows. Cert next to it.
* What it can do: sign TLS server certificates. It is limited to the
  ServerAuth extended key usage, path length zero (it cannot sign further
  CAs), and the agent mints leaf certificates only for domains on the current
  blocklist and their `www.` forms (7 days, in memory).
* What it cannot do: sign code, sign email, or impersonate a site that is not
  blocked. The agent never mints a certificate for an unlisted name, so the
  realistic risk is someone who already has root or SYSTEM on that endpoint
  stealing the key, which is the position from which they could do far more.
* Removal: turning the feature off, uninstalling the agent package, or running
  the cleanup flag removes the certificate from the trust store and deletes the
  key and certificate files.
* Provision the state directory root/SYSTEM-only. If a local user pre-creates
  `<state_dir>/webblock`, the agent refuses to install the CA (it fails safe:
  the health shows an error and nothing is trusted).

## Browsers

* Windows Chrome and Edge use the system store and show the block page.
* Firefox on Windows uses its own store unless `ImportEnterpriseRoots` is set
  to true in its enterprise policy; without it the domain is blocked but
  Firefox shows a certificate error.
* Linux desktop browsers (Firefox, Chrome, Chromium) use their own NSS store.
  The domain is blocked but the browser shows a certificate error for HTTPS.
  `curl` and other tools using the system store show the page. HTTP pages work
  everywhere.
* Browser DNS over HTTPS bypasses the hosts file. Disable it by policy (for
  example Firefox `DNSOverHTTPS` locked off, Chrome/Edge `DnsOverHttpsMode`
  `off`) or the block will not apply.

## Troubleshooting

| Symptom | Meaning and fix |
| --- | --- |
| `page_server: page_unavailable: ...` | The agent could not bind one or more of `127.84.0.1:80/443` or `[::1]:80/443` (another program is using the port). Blocked names still resolve to the local address but get a connection error instead of the page. Find the owner with `ss -ltnp` or `netstat -ano` and stop it; the agent retries on its next re-check. |
| `hosts_tampered: true` | The hosts block markers were found damaged or edited by something else. The agent rewrites its block on the next re-check (every 5 minutes) and reports until it is intact. Repeated tampering usually points to another tool managing the hosts file or to a user editing it. |
| Domain still reachable | Flush the DNS cache (`ipconfig /flushdns` on Windows; `resolvectl flush-caches` on systemd-resolved). The agent flushes after changes, but browsers keep their own cache and DoH skips the hosts file. |
| Certificate error on a blocked HTTPS site | The CA is not trusted by that program (see Browsers), or `ca_installed` is false in health; check `last_error`. |

Notes on the hosts file write: it is replaced through a temp file and a rename
in the same directory. Where that is impossible (a Docker bind-mounted
`/etc/hosts`, or Windows when the file is locked) the agent writes in place,
which truncates the file before writing; a full disk in the middle of such a
write can leave the hosts file truncated. Keep free space on those systems.

## Removing everything without the server

Linux (as root):

```
sudo /usr/bin/siem-agent -webblock-cleanup -config /etc/siem-agent/config.yaml
```

Windows (elevated prompt):

```
"C:\Program Files\SIEMAgent\siem-agent.exe" -webblock-cleanup -config "%ProgramData%\SIEMAgent\config.yaml"
```

It must run as root or Administrator, because it edits the hosts file and the
trust store.

This removes the hosts block, the CA from the trust store, the CA files and the
saved list, with no network access and without a running agent. Package removal
runs it for you (deb `prerm`, rpm `%preun`, MSI deferred custom action as
SYSTEM). It exits non-zero only when the hosts block could not be removed.

## Testing

`go test ./agent/internal/webblock/...` covers the logic without touching the
machine. The end-to-end test changes the real hosts file and trust store, so it
runs only when `WEBBLOCK_E2E=1` and the process is root or elevated. CI runs it
on the Ubuntu runner and on `windows-latest`:

```
cd agent && sudo -E env "PATH=$PATH" WEBBLOCK_E2E=1 go test -count=1 -run E2E -v ./internal/webblock/
```

On Windows (elevated pwsh):

```
go test ./agent/internal/webblock/... -count=1
$env:WEBBLOCK_E2E = '1'; go test ./agent/internal/webblock -run E2E -count=1 -v
```
