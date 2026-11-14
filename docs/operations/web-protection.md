# Web protection (agent)

Web protection stops endpoints from reaching domains on the server's web
blocklist (manual entries, alert-derived domains, URLhaus and PhishTank). The
agent shows a block page instead of the site and reports each attempt to the
SIEM as a `web_block` event.

## What the agent does

When the group's policy enables it, the agent:

1. Syncs the blocklist from `POST /api/ingest/web-blocklist` and keeps it in
   `<state_dir>/webblock/list.json` (the protected directory that also holds
   the CA). Agents before this version kept it in `<state_dir>/webblock.json`;
   that file is deleted on start, never loaded.
2. Writes a block between `# BEGIN ADSIEM WEBBLOCK` and `# END ADSIEM WEBBLOCK`
   in the hosts file. Each domain and `www.<domain>` points to `127.84.0.1`;
   on Windows also to `::1` while the IPv6 listeners are up. Linux writes no
   `::1` entries (see below). Lines outside the block are never changed. The
   block grows with the list: two lines per domain on Linux (the name and its
   `www.` form), four on Windows with IPv6, so 50,000 domains is about
   100,000 lines on Linux.
3. Serves the block page for `127.84.0.1:80` and `127.84.0.1:443` (Windows
   also `[::1]:80` and `[::1]:443`). Every request gets `403` with the page.
   HTTPS uses a leaf certificate minted for the requested name from the
   per-endpoint CA.
4. Installs that CA in the system trust store so HTTPS shows the page instead
   of a certificate error.
5. Emits `event=web_block action=blocked domain=... scheme=... path=...
   source=... reason="..."`, with `process` and `pid` when known, at most one
   line per domain and process per minute (`count=N` for the suppressed hits).
   Only requests for a listed domain are reported: the page answers any name,
   but a local program sending a made-up `Host` header gets no event. HTTPS
   events carry the domain only (`path=""`); HTTP events keep the path.

Turning the feature off for the group (or deleting the policy) reverses every
step: hosts block removed, page server and its redirect stopped, CA removed
from the trust store, CA files and saved list deleted.

### How the page server listens (Linux and Windows differ)

On Linux a socket listening on `127.84.0.1:80` makes any later bind of
`0.0.0.0:80` or `[::]:80` fail with "address in use": nginx, Apache or
`docker run -p 80:80` would no longer start. So on Linux the agent never
listens on 80 or 443. It listens on two free high ports on `127.0.0.1` and
adds a NAT redirect for traffic to `127.84.0.1:80/443`:

* with `nft` (preferred): its own table `ip adsiem_webblock` (chain `output`,
  `type nat hook output priority -100`, two `redirect to :<port>` rules);
* else with `iptables`: its own chain `ADSIEM_WEBBLOCK` in the `nat` table,
  jumped to from `OUTPUT` for `-d 127.84.0.1 -p tcp`.

The rules are removed when the feature is turned off, when the agent stops
the page server, and by `-webblock-cleanup`. They touch only traffic to
`127.84.0.1`, so the agent's firewall table and other rules are unaffected.
The TLS name (SNI) and `Host` header are unchanged by the redirect.
After a graceful agent stop the redirect is gone and blocked names get
"connection refused" on `127.84.0.1` (still blocked). After a crash the rules
may keep pointing at a now-free high port on `127.0.0.1` until the agent
restarts; at start it removes any leftover rules of both tools (nft and
iptables) before installing its own.

When neither tool is usable the agent binds `127.84.0.1:80/443` directly, but
only a port no other service is listening on (checked in `/proc/net/tcp` and
`/proc/net/tcp6`); a busy port shows `page_unavailable: 127.84.0.1:80 (port
in use by another service)`. A failed bind is retried only when the list,
page or CA changes, never on a timer, so the agent does not grab a port from
a service that is restarting.

Linux writes no `::1` hosts entries and starts no `[::1]` listeners:
redirecting `::1` would capture legitimate local services on that address.
Blocked names resolve to `127.84.0.1` only.

On Windows the agent binds `127.84.0.1:80/443` and `[::1]:80/443` directly;
Windows lets another program bind the wildcard address on the same port
afterwards. A program that already holds a wildcard listener on 80 or 443
(HTTP.sys, see below) answers instead of the page. When IPv6 is disabled the
`[::1]` binds are skipped and health shows `page_server: ok (ipv4 only)`.

## Turning it on

Enable web protection for the group on the **Web Protection** page (the
policy is per group). Agents pick it up on the next heartbeat;
`web_blocklist_version` in the heartbeat is empty while off. Each agent's Web
Protection health (enabled, entries, version, CA installed, page server,
hosts tampered, last error) shows under **Web Protection → Agents** and in the
API (`GET /api/web-blocks/agents`). `last_error` is cut to about 280
characters by the agent; the server cuts any over-long text field to 300
instead of dropping the report.

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
* Provision the state directory root/SYSTEM-only. If `<state_dir>/webblock`
  is a symlink or reparse point, not a directory, or owned by someone other
  than the agent user (Linux) or SYSTEM/Administrators (Windows), the agent
  renames it aside to `<state_dir>/webblock.untrusted-<unixtime>`, logs a
  warning and recreates it privately. Nothing it contained is used. Inspect
  and delete the renamed entry.
* Security tools may react to the trust store change: Microsoft Defender can
  flag the hosts file edit as `SettingsModifier:Win32/HostsFileHijack`, and
  other EDRs or Sysmon rules may alert on a new root certificate. Allow-list
  the agent's changes (the `# BEGIN ADSIEM WEBBLOCK` block and the
  `ADSIEM Web Protection (<hostname>)` root) where needed.

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
| `webblock: moved an untrusted state directory aside` after every agent upgrade (Linux) | Packages before 1.27.5 chowned `/var/lib/siem-agent` recursively to `siem-agent`, so the root agent distrusted its own `webblock` directory, regenerated the CA (the trust store anchor is replaced, same file name) and refetched the list. Upgrade to 1.27.5, then delete the aside directories, which still hold the old CA private key: `rm -rf /var/lib/siem-agent/webblock.untrusted-*`. |
| `page_server: page_unavailable: ...` | Something listed could not be set up. Linux: `redirect (...)` means the nft/iptables rule failed (check the agent log); `(port in use by another service)` means no redirect tool was usable and a local service has the port. Windows: another program holds `127.84.0.1:80/443` or `[::1]:80/443`; find it with `netstat -ano`. Blocked names still resolve to the local address but get a connection error instead of the page. On Windows the agent retries every 5 minutes; on Linux on the next list, page or CA change (or an agent restart). |
| `page_server: ok (ipv4 only)` | Windows with IPv6 disabled: the page is served on `127.84.0.1` only. Nothing to fix. |
| `hosts_tampered: true` | The block markers were found damaged, or the 5-minute re-check had to rewrite the block although the list had not changed (someone deleted or edited it). The agent repairs it and keeps reporting until a re-check finds it intact or the list changes. Repeated tampering usually points to another tool managing the hosts file or to a user editing it. |
| Domain still reachable | Flush the DNS cache (`ipconfig /flushdns` on Windows; `resolvectl flush-caches` on systemd-resolved). The agent flushes after changes, but browsers keep their own cache and DoH skips the hosts file. |
| Certificate error on a blocked HTTPS site | The CA is not trusted by that program (see Browsers), or `ca_installed` is false in health; check `last_error`. |

### Windows: port 80 held by HTTP.sys/IIS

On Windows the HTTP.sys kernel driver (IIS, WinRM, and other services) often
listens on all addresses on port 80, so the agent cannot bind `127.84.0.1:80`
and health shows `page_unavailable`. Blocked domains stay blocked: the
connection reaches HTTP.sys and never the real site. Plain-HTTP visits show
HTTP.sys's own error instead of the custom page; HTTPS, which is most traffic,
shows the custom page. The agent does not change HTTP.sys configuration. An
administrator who wants the page over HTTP can restrict HTTP.sys to specific
addresses with `netsh http add iplisten`.

Notes on the hosts file write: on Linux it is replaced through a temp file and
a rename in the same directory, or written in place where a rename is
impossible (a Docker bind-mounted `/etc/hosts`). Windows always writes the
hosts file in place. An in-place write truncates the file before writing; a
full disk in the middle of such a write can leave the hosts file truncated.
Keep free space on those systems.

## Removing everything without the server

Linux (as root):

```
sudo /usr/bin/siem-agent -webblock-cleanup -config /etc/siem-agent/config.yaml
```

Windows (elevated prompt):

```
"C:\Program Files\SIEMAgent\siem-agent.exe" -webblock-cleanup -config "%ProgramData%\SIEMAgent\config.yaml"
```

It must run as root or Administrator, because it edits the hosts file, the
trust store and (Linux) the nft/iptables rules.

Stop the agent service first (`systemctl stop siem-agent`, `sc stop
SIEMAgent`): a running agent with the feature on re-applies everything within
5 minutes.

This removes the hosts block, the Linux redirect (nft table
`adsiem_webblock`, iptables chain `ADSIEM_WEBBLOCK`), the CA from the trust
store, the CA files and the saved list (also the old `<state_dir>/webblock.json`),
with no network access and without a running agent. If the config cannot be
read it logs the error and uses the default state directory
(`/var/lib/siem-agent`, `%ProgramData%\SIEMAgent`); the hosts block, redirect
and trust store entry are removed either way. Package removal runs it for you
(deb `prerm`, rpm `%preun`, MSI deferred custom action as SYSTEM). It exits
non-zero when the hosts block could not be removed or the config could not be
read.

Downgrading to an agent version without Web Protection does not remove
anything: the old agent does not know the hosts block, CA or redirect. Run
`-webblock-cleanup` (with the agent stopped) before the downgrade.

## Testing

`go test ./agent/internal/webblock/...` covers the logic without touching the
machine. The end-to-end test changes the real hosts file, trust store and (Linux)
nft/iptables rules, so it runs only when `WEBBLOCK_E2E=1` and the process is
root or elevated. On Linux it also checks that `0.0.0.0:80` and `:443` can
still be bound while the page server is up, and it fails with a clear message
when neither `nft` nor `iptables` is usable on the runner. CI runs it
on the Ubuntu runner and on `windows-latest`:

```
cd agent && sudo -E env "PATH=$PATH" WEBBLOCK_E2E=1 go test -count=1 -run E2E -v ./internal/webblock/
```

On Windows (elevated pwsh):

```
go test ./agent/internal/webblock/... -count=1
$env:WEBBLOCK_E2E = '1'; go test ./agent/internal/webblock -run E2E -count=1 -v
```
