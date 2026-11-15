# Retro-hunt

A retro-hunt answers "was this already here?" for an indicator or a rule
learnt today. It searches the logs already stored in Elasticsearch, not just
new traffic.

Dashboard: **Investigation → Retro-hunt**. API: `POST/GET /api/retro-hunts`.

## Indicator hunts

Types: `ip`, `domain`, `hash`, `url`, `text`. The worker matches the value as a
phrase in `raw_message` (and `source_ip` for IPs) across the chosen number of
days, then groups the hits per host with first/last seen and three sample lines.

With *Raise alerts* on (the default) every host that saw the indicator gets one
high alert titled `Retro-hunt: <TYPE> <value> Seen In Past Logs`.

Hunts start automatically when an indicator is blocked:

| Action | Trigger | Scope |
|---|---|---|
| IP added to the IP blocklist (single address, not a CIDR) | `ip_block` | the entry's group |
| Domain blocked in Web Protection | `web_block` | the entry's group |
| Hashes added to Malware hashes (first 20 per request) | `malware_hash` | all groups |

The same indicator is queued at most once an hour. Turn automatic hunts off with
the setting `retro_hunt_on_block = false`; `retro_hunt_days` (default 30) sets
how far back they look.

## Rule hunts

Runs one detection rule over past events of the rule's log types. Limits:
200,000 events evaluated and 500 matches; the result says when it stopped at the
limit. Correlation (threshold/sequence) rules are refused. Rule hunts do not
raise alerts unless asked, so testing a noisy rule does not flood the queue.

## Access

Starting a hunt needs `alerts:manage`. A user scoped to a group hunts only in
that group and sees only that group's hunts; a superadmin hunts all groups (`*`)
unless a group is given.
