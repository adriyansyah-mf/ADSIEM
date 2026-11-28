"""Entities an alert names (host, user, process, file, hash, IP, domain) and
how they connect, for a case's relation graph. Pure: callers pass the event's
decoded fields merged with the rule's matched_fields."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

USER_FIELDS = ("user.name", "winlog.event_data.TargetUserName", "TargetUserName", "winlog.event_data.User",
               "User", "SubjectUserName", "user.target", "srcuser", "dstuser")
PROCESS_FIELDS = ("process.executable", "Image", "winlog.event_data.Image", "process.name")
PARENT_FIELDS = ("process.parent.executable", "ParentImage", "winlog.event_data.ParentImage", "process.parent.name")
FILE_FIELDS = ("file.path", "TargetFilename", "winlog.event_data.TargetFilename", "file.name")
HASH_FIELDS = ("file.hash.sha256", "process.hash.sha256", "hash.sha256", "sha256", "Hashes", "winlog.event_data.Hashes")
IP_FIELDS = ("destination.ip", "DestinationIp", "winlog.event_data.DestinationIp", "dst_ip", "dstip",
             "source.ip", "SourceIp", "src_ip", "srcip")
DOMAIN_FIELDS = ("dns.question.name", "QueryName", "winlog.event_data.QueryName", "url.domain", "destination.domain")
IGNORED_USERS = {"system", "local service", "network service", "-", "n/a", "anonymous logon"}
_SHA256 = re.compile(r"(?:SHA256=)?\b([a-fA-F0-9]{64})\b")
MAX_VALUE = 260


@dataclass
class AlertEntities:
    entities: list[tuple[str, str]] = field(default_factory=list)   # (kind, value), first one per kind is the "main"
    edges: list[tuple[str, str]] = field(default_factory=list)      # ("kind:value", "kind:value")

    def add(self, kind: str, value: str | None) -> str | None:
        if not value:
            return None
        value = value.strip()[:MAX_VALUE]
        if not value:
            return None
        if (kind, value) not in self.entities:
            self.entities.append((kind, value))
        return f"{kind}:{value}"

    def link(self, a: str | None, b: str | None) -> None:
        if a and b and a != b and (a, b) not in self.edges and (b, a) not in self.edges:
            self.edges.append((a, b))


def _first(fields: dict, names: tuple[str, ...]) -> str | None:
    for name in names:
        value = fields.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        if value not in (None, ""):
            return str(value)
    return None


def _user(fields: dict) -> str | None:
    for name in USER_FIELDS:
        value = fields.get(name)
        if value in (None, ""):
            continue
        user = str(value).strip()
        if user.lower() not in IGNORED_USERS and not user.endswith("$"):
            return user
    return None


def _hash(fields: dict) -> str | None:
    raw = _first(fields, HASH_FIELDS)
    match = _SHA256.search(raw) if raw else None
    return match.group(1).lower() if match else None


def _ips(fields: dict) -> list[str]:
    out = []
    for name in IP_FIELDS:
        value = fields.get(name)
        if value in (None, ""):
            continue
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or str(ip) in out:
            continue
        out.append(str(ip))
    return out


def alert_entities(fields: dict | None, hostname: str | None, source_ip: str | None) -> AlertEntities:
    fields = fields or {}
    out = AlertEntities()
    host = out.add("host", hostname)
    user = out.add("user", _user(fields))
    out.link(user, host)
    parent = out.add("process", _first(fields, PARENT_FIELDS))
    process = out.add("process", _first(fields, PROCESS_FIELDS))
    out.link(parent, process)
    out.link(host, parent or process)
    actor = process or parent or host
    out.link(out.add("file", _first(fields, FILE_FIELDS)), actor)
    out.link(out.add("hash", _hash(fields)), actor)
    for ip in _ips(fields) or ([source_ip] if source_ip else []):
        out.link(actor, out.add("ip", ip))
    out.link(actor, out.add("domain", _first(fields, DOMAIN_FIELDS)))
    return out
