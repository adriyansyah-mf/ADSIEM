# worker/worker/case_grouping.py
"""Which case an alert belongs in.

A case is one attacker's campaign:

- an alert's campaign keys are the attacker-controlled IOCs it carries (public
  source IP, file hashes, and for outbound behaviour the contacted IP, domain
  or URL — see ioc_keys); hosts and users are never keys;
- an alert joins the active case sharing any of its keys, on whichever host it
  fired; the host is added to the case's affected hosts, and other active cases
  sharing a key are merged in (or linked, if an analyst is already on them);
- an alert without keys (a local privilege escalation, persistence, …) joins
  the campaign already on its host;
- every alert has an attack *family* (its furthest kill-chain tactic, from the
  rule's ATT&CK tags; else the triage's threat_type; else its title). It no
  longer splits cases: a case keeps its furthest stage, and a post-compromise
  family after credential/initial access raises it to critical;
- a different attacker on the same host gets its own case, linked to the others;
- failed-only brute force from public addresses goes into one digest case per
  group per day instead of one case per IP.
"""
from __future__ import annotations

import ipaddress
import re

# Kill-chain order: the alert's family is its furthest tactic.
KILL_CHAIN = [
    "reconnaissance", "resource_development", "initial_access", "credential_access", "discovery",
    "execution", "persistence", "privilege_escalation", "defense_evasion", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]
TACTIC_ALIASES = {"recon": "reconnaissance", "c2": "command_and_control"}

# Families that mean the attacker got in (after brute force / exploitation attempts).
POST_COMPROMISE = {
    "execution", "persistence", "privilege_escalation", "defense_evasion", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
}
PRE_COMPROMISE = {"reconnaissance", "credential_access", "initial_access", "discovery"}

THREAT_TYPE_FAMILY = {
    "brute_force": "credential_access", "scan": "reconnaissance", "malware": "execution",
    "c2": "command_and_control", "exfiltration": "exfiltration", "lateral_movement": "lateral_movement",
    "privilege_escalation": "privilege_escalation",
}

_TITLE_HINTS = [
    (re.compile(r"(?i)after brute|login after|successful login after"), "initial_access"),
    (re.compile(r"(?i)brute|password spray|failed (login|logon|su|sudo)|credential stuffing|account locked"),
     "credential_access"),
    (re.compile(r"(?i)scan|enumeration|probe|recon"), "reconnaissance"),
    (re.compile(r"(?i)reverse shell|webshell|command injection|rce|shellshock|log4|exploit"), "initial_access"),
    (re.compile(r"(?i)persistence|cron|scheduled task|service install|run key|authorized_keys|new user|user created"),
     "persistence"),
    (re.compile(r"(?i)sudo|privilege|admin group|root"), "privilege_escalation"),
    (re.compile(r"(?i)beacon|c2|callback"), "command_and_control"),
    (re.compile(r"(?i)exfil"), "exfiltration"),
    (re.compile(r"(?i)log cleared|disable security|tamper"), "defense_evasion"),
    (re.compile(r"(?i)powershell|process|execution|miner"), "execution"),
]


def _tactic(tag: str) -> str | None:
    t = str(tag).lower()
    if not t.startswith("attack.") or t[7:8] == "t" and t[8:9].isdigit():
        return None
    name = TACTIC_ALIASES.get(t[7:].replace("-", "_"), t[7:].replace("-", "_"))
    return name if name in KILL_CHAIN else None


def attack_family(tags: list | None = None, threat_type: str | None = None, title: str = "") -> str:
    tactics = {t for t in (_tactic(x) for x in tags or []) if t}
    if tactics:
        return max(tactics, key=KILL_CHAIN.index)
    if threat_type in THREAT_TYPE_FAMILY:
        return THREAT_TYPE_FAMILY[threat_type]
    for rx, family in _TITLE_HINTS:
        if rx.search(title or ""):
            return family
    return "other"


def is_public_ip(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def is_failed_bruteforce(tags: list | None, title: str, family: str) -> bool:
    """Password guessing that hasn't succeeded: T1110 credential access (or a
    brute-force title), not the brute-force-then-success rule."""
    if family != "credential_access":
        return False
    if re.search(r"(?i)after brute|success", title or ""):
        return False
    techniques = {str(t).lower() for t in tags or []}
    return any(t.startswith("attack.t1110") for t in techniques) or bool(
        re.search(r"(?i)brute|password spray|failed (login|logon)|user enumeration|account locked", title or ""))


def raises_to_critical(new_family: str, related_families: set[str]) -> bool:
    """A post-compromise family on an entity already under credential/initial-access attack."""
    return new_family in POST_COMPROMISE and bool(related_families & {"credential_access", "initial_access"})


def further_stage(a: str | None, b: str | None) -> str | None:
    """The later of two families on the kill chain ('other' and unknowns rank lowest)."""
    rank = {f: i for i, f in enumerate(KILL_CHAIN)}
    if not a:
        return b
    if not b:
        return a
    return b if rank.get(b, -1) > rank.get(a, -1) else a


# ─── Campaign keys: which IOCs tie alerts on different hosts together ───────
# A case is one attacker's campaign: alerts sharing an attacker-controlled
# indicator join it whichever host they fired on, and the host becomes one of
# its affected hosts. Hosts and usernames are never keys — two attackers on
# the same server are two cases. Only indicators the attacker controls count:
# public source IPs, file hashes, and — for outbound behaviour (C2, exfil,
# download-and-run) — the public IP, domain or URL being contacted. On inbound
# alerts the destination is our own server, so it is never a key there.

OUTBOUND_FAMILIES = {"command_and_control", "exfiltration", "execution"}

# Shared infrastructure that would chain unrelated alerts together.
DEFAULT_IOC_EXCLUSIONS = (
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "microsoft.com", "windowsupdate.com", "windows.com", "office.com", "google.com", "googleapis.com",
    "gstatic.com", "ubuntu.com", "debian.org", "fedoraproject.org", "github.com", "githubusercontent.com",
    "amazonaws.com", "cloudflare.com", "akamaiedge.net",
)

_DEST_IP_FIELDS = ("destination.ip", "DestinationIp", "dst_ip", "dstip", "RemoteAddr")
_DOMAIN_FIELDS = ("destination.domain", "url.domain", "dns.question.name", "QueryName", "DestinationHostname")
_URL_FIELDS = ("url.full", "url.original")
_HASH_FIELDS = ("file.hash.sha256", "file.hash.sha1", "file.hash.md5", "hash.sha256", "hash.md5",
                "SHA256", "SHA1", "MD5", "sha256", "md5")
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")


def parse_exclusions(setting: str | None) -> tuple[list, set[str]]:
    """(networks, domains) from the defaults plus Settings → case_ioc_exclusions
    (comma/newline separated IPs, CIDRs and domains — e.g. your own public IPs)."""
    nets, domains = [], set()
    for raw in [*DEFAULT_IOC_EXCLUSIONS, *re.split(r"[,\s]+", setting or "")]:
        item = raw.strip().lower().rstrip(".")
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            domains.add(item)
    return nets, domains


def _ip_key(value, nets) -> str | None:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if not ip.is_global or any(ip in n for n in nets):
        return None
    return f"ip:{ip}"


def _domain_key(value, domains) -> str | None:
    d = str(value or "").strip().lower().rstrip(".")
    if not d or "." not in d or _ip_key(d, []) or any(d == x or d.endswith("." + x) for x in domains):
        return None
    return f"domain:{d}"


def _url_key(value, domains) -> str | None:
    u = str(value or "").strip()
    m = re.match(r"(?i)^[a-z][a-z0-9+.-]*://([^/:?#]+)", u)
    if not m:
        return None
    host = m.group(1).lower()
    if any(host == x or host.endswith("." + x) for x in domains):
        return None
    return f"url:{u.lower()}"


def ioc_keys(family: str, source_ip: str | None, fields: dict | None, extracted: list | None,
             exclusions: tuple[list, set[str]]) -> list[str]:
    """The campaign keys of one alert (see above). `extracted` are TI-extracted
    IOCs (objects or dicts with type/value)."""
    nets, domains = exclusions
    fields = fields or {}
    outbound = family in OUTBOUND_FAMILIES
    keys = {_ip_key(source_ip, nets)} if source_ip else set()

    for name in _HASH_FIELDS:
        for h in _HASH_RE.findall(str(fields.get(name) or "")):
            keys.add(f"hash:{h.lower()}")
    if "Hashes" in fields:  # Sysmon: "SHA256=…,MD5=…"
        keys.update(f"hash:{h.lower()}" for h in _HASH_RE.findall(str(fields["Hashes"])))
    if outbound:
        keys.update(_ip_key(fields.get(n), nets) for n in _DEST_IP_FIELDS if fields.get(n))
        keys.update(_domain_key(fields.get(n), domains) for n in _DOMAIN_FIELDS if fields.get(n))
        keys.update(_url_key(fields.get(n), domains) for n in _URL_FIELDS if fields.get(n))

    for ioc in extracted or []:
        kind = getattr(getattr(ioc, "type", None), "value", None) or (ioc.get("type") if isinstance(ioc, dict) else None)
        value = getattr(ioc, "value", None) or (ioc.get("value") if isinstance(ioc, dict) else None)
        if not kind or not value:
            continue
        if kind.startswith("hash_"):
            keys.add(f"hash:{str(value).lower()}")
        elif outbound and kind in ("ipv4", "ipv6"):
            keys.add(_ip_key(value, nets))
        elif outbound and kind == "domain":
            keys.add(_domain_key(value, domains))
        elif outbound and kind == "url":
            keys.add(_url_key(value, domains))
    return sorted(k for k in keys if k)
