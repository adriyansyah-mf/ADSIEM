# Agentless syslog ingest

Firewalls, switches, VPN concentrators and other appliances that can't run the
agent send syslog to the `syslog-receiver` service. Each message joins the same
Redis stream the agents feed (`siem:logs`), so decoders, Sigma rules, UEBA,
alerting, cases and SOAR treat it like any agent log line.

```
device ──UDP/TCP 514──▶ syslog-receiver ──XADD──▶ siem:logs ──▶ worker (decode → Sigma → alert)
                             │
                             └── syslog_sources (Postgres): sender CIDR → group + log type
```

## Formats

| Input | What the decoders see |
|---|---|
| RFC 3164 `<PRI>Mmm dd hh:mm:ss host tag: msg` | the line without `<PRI>`: the same text the agent tails from `/var/log/*` |
| RFC 5424 `<PRI>1 TS HOST APP PROCID MSGID [SD] MSG` | rewritten as `Mmm dd hh:mm:ss HOST APP[PROCID]: MSG`. Structured data is dropped |
| Headerless (FortiGate `<189>date=… devname=…`) | the line without `<PRI>` |
| CEF (`CEF:0|vendor|product|…`), alone or after a syslog header | unchanged; the `cef` decoder type parses it |

TCP accepts newline/NUL-delimited and octet-counted (RFC 6587) framing. Each
message is capped at 64 KiB. TLS (RFC 5425) isn't supported yet, so for traffic
crossing untrusted networks use a VPN or a local relay.

## Registering a device

Open **Environment → Syslog devices** (`/syslog`), or call the API:

```bash
curl -X POST https://siem/api/syslog-sources -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "FortiGate HQ", "cidr": "10.0.5.1", "log_type": "fortigate_traffic"}'
```

- **cidr**: a single address or a network. The most specific match wins. A
  network can be registered only once, across all groups.
- **log_type**: picks the decoders. `fortigate_traffic` (FortiGate), `cef` (any
  CEF sender, via `decoders/cef_generic.yaml`), `linux_auth` / `syslog`
  (rsyslog forwarding from Linux hosts), or your own decoder's log type.
- **group**: always the caller's group. A superadmin may pass `group_id`.
- Networks broader than /16 (IPv4) or /48 (IPv6) need a superadmin, so one group
  can't capture other groups' unregistered senders.

Writes need `agents:manage` and are audit-logged (`syslog_source.create|update|delete`).
Changes reach the receiver within 15 seconds.

**Messages from unregistered senders are dropped.** The receiver remembers them
for 7 days (Redis `siem:syslog:unknown`: count, last seen, a 300-character
sample), and a superadmin sees them under *Unregistered senders* on the page or
at `GET /api/syslog-sources/unknown`. Registering the address clears the entry.

## Device examples

FortiGate (FortiOS 7):

```
config log syslogd setting
    set status enable
    set server "<siem-host>"
    set mode udp            # or reliable (TCP, octet-counted)
    set port 514
end
```

rsyslog on a Linux host (`/etc/rsyslog.d/90-siem.conf`), registered with log type `linux_auth`:

```
auth,authpriv.*  @@<siem-host>:514   # @@ = TCP, @ = UDP
```

Any CEF sender: point it at `<siem-host>:514` and register it with log type `cef`.
For vendor-specific field mappings, add a decoder with `type: cef`, the same
`log_type` and a lower `priority` than 50, plus `match: <vendor name>`.

## Deployment

`docker-compose.yml` runs `syslog-receiver` from the worker image
(`python -m worker.syslog_receiver`). It listens on 5514 inside the container,
and the host publishes `${SYSLOG_PORT:-514}` for both UDP and TCP. If the host's
own rsyslog already binds 514, set `SYSLOG_PORT` to another port or turn off
rsyslog's network input.

With Docker's default iptables port publishing, the sender's real source address
is preserved. Behind a NAT or a load balancer that rewrites the source, every
sender arrives with the same address, so register that address instead.

| Env | Default | |
|---|---|---|
| `SYSLOG_UDP_PORT` / `SYSLOG_TCP_PORT` | 5514 | listen ports inside the container |
| `SYSLOG_BIND` | 0.0.0.0 | |
| `SYSLOG_QUEUE_SIZE` | 50000 | in-memory backlog while Redis is unreachable; beyond it, messages are dropped |
| `SYSLOG_METRICS_PORT` | 8002 | Prometheus metrics (also the health check) |

Metrics: `siem_syslog_received_total{proto}`, `siem_syslog_enqueued_total`,
`siem_syslog_dropped_total{reason=unknown_source|backlog_full|empty|bad_peer}`,
`siem_syslog_sources`, `siem_syslog_backlog`. Each source's message count and
last-message time are written to `syslog_sources` every 30 seconds and shown on
the page. A device that goes quiet is visible from its *Last message* column.

Syslog events have no agent, so agent-only actions (live response, isolation)
don't apply to them. Their `hostname` is the syslog header's host, or the
source's name when the header has none. `location` is `syslog://<sender-ip>`.
