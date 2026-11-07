# worker/worker/alert_iocs.py
"""Attacker indicators per alert, in the Elasticsearch index `alert_iocs`.

One document per (alert, indicator), id = sha1(alert_id|type|value), so writing
an alert again (after AI triage, or a backfill) overwrites instead of
duplicating. Unlike case_grouping.ioc_keys, domains and URLs are kept for every
alert family: this is an inventory, not a campaign key. Elasticsearch failures
are logged and never raised — alert creation and triage must not depend on it."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime

import structlog

from worker import es_client
from worker.case_grouping import (
    _DEST_IP_FIELDS, _DOMAIN_FIELDS, _HASH_FIELDS, _HASH_RE, _URL_FIELDS, parse_exclusions,
)

log = structlog.get_logger()

INDEX = "alert_iocs"
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_EMAIL_FIELDS = ("user.email", "email.from.address", "email.to.address", "SenderAddress", "RecipientAddress")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://([^/:?#]+)")
_HASH_TYPES = {64: "sha256", 40: "sha1", 32: "md5"}
_TI_TYPES = {"ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url",
             "hash_md5": "md5", "hash_sha1": "sha1", "hash_sha256": "sha256"}
_DELETE_BATCH = 1000

_KEYWORD = {"type": "keyword"}
MAPPING = {"mappings": {"properties": {
    "alert_id": _KEYWORD, "group_id": _KEYWORD, "type": _KEYWORD, "value": _KEYWORD, "ioc_key": _KEYWORD,
    "severity": _KEYWORD, "severity_rank": {"type": "byte"}, "hostname": _KEYWORD, "agent_id": _KEYWORD,
    "rule_title": _KEYWORD, "ai_verdict": _KEYWORD, "origin": _KEYWORD, "created_at": {"type": "date"},
}}}


@dataclass(frozen=True)
class AlertMeta:
    alert_id: str
    group_id: str
    severity: str
    hostname: str | None
    agent_id: str | None
    rule_title: str
    created_at: datetime
    ai_verdict: str | None = None


def doc_id(alert_id: str, ioc_type: str, value: str) -> str:
    return hashlib.sha1(f"{alert_id}|{ioc_type}|{value}".encode()).hexdigest()


def _excluded_host(host: str, domains: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _ip(value, nets) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if not ip.is_global or any(ip in n for n in nets):
        return None
    return str(ip)


def _domain(value, domains) -> str | None:
    d = str(value or "").strip().lower().rstrip(".")
    if not d or "." not in d or _ip(d, []) or _excluded_host(d, domains):
        return None
    try:
        return d.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _url(value, domains) -> str | None:
    u = str(value or "").strip()
    m = _URL_RE.match(u)
    if not m or _excluded_host(m.group(1).lower(), domains):
        return None
    return u.lower()


def _email(value) -> str | None:
    e = str(value or "").strip().lower()
    return e if _EMAIL_RE.match(e) else None


def _extracted(item) -> tuple[str | None, str | None]:
    if isinstance(item, dict):
        kind, value = item.get("type"), item.get("value")
    else:
        kind = getattr(getattr(item, "type", None), "value", None) or getattr(item, "type", None)
        value = getattr(item, "value", None)
    return (str(kind) if kind else None), (str(value) if value else None)


def collect(meta: AlertMeta, source_ip: str | None, fields: dict | None, extracted: list | None,
            exclusions: tuple[list, set[str]], *, extracted_origin: str = "ti") -> list[tuple[str, dict]]:
    """(doc_id, document) for every indicator of one alert, first origin wins."""
    nets, domains = exclusions
    fields = fields or {}
    found: dict[tuple[str, str], str] = {}

    def add(kind: str, value: str | None, origin: str) -> None:
        if value and (kind, value) not in found:
            found[(kind, value)] = origin

    add("ip", _ip(source_ip, nets), "alert")
    for name in _DEST_IP_FIELDS:
        add("ip", _ip(fields.get(name), nets), "event")
    for name in _DOMAIN_FIELDS:
        add("domain", _domain(fields.get(name), domains), "event")
    for name in _URL_FIELDS:
        add("url", _url(fields.get(name), domains), "event")
    for name in (*_HASH_FIELDS, "Hashes"):
        for h in _HASH_RE.findall(str(fields.get(name) or "")):
            add(_HASH_TYPES[len(h)], h.lower(), "event")
    for name in _EMAIL_FIELDS:
        add("email", _email(fields.get(name)), "event")

    for item in extracted or []:
        kind, value = _extracted(item)
        mapped = _TI_TYPES.get(kind or "")
        if mapped == "ip":
            add("ip", _ip(value, nets), extracted_origin)
        elif mapped == "domain":
            add("domain", _domain(value, domains), extracted_origin)
        elif mapped == "url":
            add("url", _url(value, domains), extracted_origin)
        elif mapped and value and len(value) == {"sha256": 64, "sha1": 40, "md5": 32}[mapped]:
            add(mapped, value.lower(), extracted_origin)

    return [(doc_id(meta.alert_id, kind, value), {
        "alert_id": meta.alert_id, "group_id": meta.group_id, "type": kind, "value": value,
        "ioc_key": f"{kind}:{value}", "severity": meta.severity,
        "severity_rank": SEVERITY_RANK.get(meta.severity, 0), "hostname": meta.hostname,
        "agent_id": meta.agent_id, "rule_title": meta.rule_title, "ai_verdict": meta.ai_verdict,
        "origin": origin, "created_at": meta.created_at.isoformat(),
    }) for (kind, value), origin in found.items()]


async def ensure_index() -> None:
    """Idempotent: create `alert_iocs` with its mapping when missing."""
    client = es_client._get_client()
    try:
        if (await client.head(f"/{INDEX}")).status_code == 200:
            return
        resp = await client.put(f"/{INDEX}", json=MAPPING)
        if resp.status_code not in (200, 201) and "resource_already_exists_exception" not in resp.text:
            log.error("alert_iocs_index_create_failed", status=resp.status_code, body=resp.text[:500])
    except Exception as exc:  # Elasticsearch down at start: the next start retries
        log.error("alert_iocs_index_create_failed", error=str(exc))


async def index_docs(docs: list[tuple[str, dict]]) -> None:
    if not docs:
        return
    lines = []
    for _id, doc in docs:
        lines.append(json.dumps({"index": {"_index": INDEX, "_id": _id}}))
        lines.append(json.dumps(doc, default=str))
    try:
        resp = await es_client._get_client().post(
            "/_bulk", content="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("errors"):
            failed = [i["index"]["error"] for i in result.get("items", []) if i.get("index", {}).get("error")]
            log.warning("alert_iocs_index_partial", failed=len(failed), first=str(failed[:1])[:300])
    except Exception as exc:
        log.warning("alert_iocs_index_failed", docs=len(docs), error=str(exc))


async def delete_for_alerts(alert_ids: list[str]) -> None:
    client = es_client._get_client()
    for start in range(0, len(alert_ids), _DELETE_BATCH):
        batch = alert_ids[start:start + _DELETE_BATCH]
        try:
            resp = await client.post(f"/{INDEX}/_delete_by_query", params={"conflicts": "proceed"},
                                     json={"query": {"terms": {"alert_id": batch}}}, timeout=60)
            if resp.status_code != 404:
                resp.raise_for_status()
        except Exception as exc:
            log.warning("alert_iocs_delete_failed", alerts=len(batch), error=str(exc))
