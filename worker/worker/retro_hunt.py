"""Retro-hunt: search the stored logs for something learnt today.

A new indicator (an IP, domain, hash or URL added to a blocklist, or entered
by an analyst) is searched for in the logs of the last N days. Every host
that saw it gets one alert ("seen in past logs") with first and last
sighting, count and sample lines. That answers the first question about a new
IOC: has it already been here?

A rule retro-hunt runs one Sigma rule over the stored events its logsource
covers (paged through an Elasticsearch point in time, capped). The result is
a report of what the rule would have caught, and alerts too when asked.

Jobs are retro_hunts rows (server-api creates them); this loop runs pending
ones one at a time."""
from __future__ import annotations

import asyncio
import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from sqlalchemy import select, update

from worker import es_client
from worker.database import AsyncSessionLocal
from worker.models import Agent, RetroHunt, Rule
from worker.sigma_logsource import SOURCES, has_logsource, logsource_matches

log = structlog.get_logger()

POLL_SECONDS = 15
MAX_HOSTS = 50          # host buckets per IOC
SAMPLES_PER_HOST = 3
RULE_PAGE = 1000
RULE_MAX_SCANNED = 200_000
RULE_MAX_MATCHES = 500
IOC_TYPES = ("ip", "domain", "hash", "url", "text")


# ─── IOC hunts ───────────────────────────────────────────────────

def _since(days: int, now: datetime | None = None) -> str:
    return ((now or datetime.now(timezone.utc)) - timedelta(days=max(days, 1))).isoformat()


def ioc_query(ioc_type: str, value: str, group_id: str, days: int, now: datetime | None = None) -> dict:
    """Every stored log line that carries the indicator, in the group, in the window.
    raw_message is the line as received, so a phrase match finds the value in any
    field of any log type (an IP as source or destination, a domain in a DNS query,
    a URL or a TLS SNI, a hash in a process or file event)."""
    value = value.strip()
    should: list[dict] = [{"match_phrase": {"raw_message": value}}]
    if ioc_type == "ip":
        should.append({"term": {"source_ip": value}})
    filters: list[dict] = [{"range": {"created_at": {"gte": _since(days, now)}}}]
    if group_id and group_id != "*":
        filters.append({"term": {"group_id": group_id}})
    return {"bool": {"filter": filters, "should": should, "minimum_should_match": 1}}


def ioc_search_body(query: dict) -> dict:
    return {
        "size": 0, "track_total_hits": True, "query": query,
        "aggs": {"hosts": {
            "terms": {"field": "agent_id", "size": MAX_HOSTS, "missing": "_none_"},
            "aggs": {
                "first": {"min": {"field": "created_at"}},
                "last": {"max": {"field": "created_at"}},
                "group": {"terms": {"field": "group_id", "size": 1}},
                "samples": {"top_hits": {"size": SAMPLES_PER_HOST, "sort": [{"created_at": "desc"}],
                                         "_source": ["raw_message", "log_type", "created_at", "group_id"]}},
            },
        }},
    }


def valid_ioc(ioc_type: str, value: str) -> str | None:
    """The normalised value, or None when it is not an indicator of that type."""
    value = (value or "").strip()
    if not value or len(value) > 2048 or ioc_type not in IOC_TYPES:
        return None
    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if ioc_type == "hash":
        v = value.lower()
        return v if len(v) in (32, 40, 64) and all(c in "0123456789abcdef" for c in v) else None
    if ioc_type == "domain":
        v = value.lower().rstrip(".")
        return v if "." in v and " " not in v and "/" not in v else None
    return value if len(value) >= 4 else None  # url, text: a phrase, not a single letter


def ioc_title(ioc_type: str, value: str) -> str:
    label = {"ip": "IP", "domain": "Domain", "hash": "File hash", "url": "URL", "text": "Indicator"}[ioc_type]
    return f"Retro-hunt: {label} {value[:120]} Seen In Past Logs"


async def _hostnames(agent_ids: list[str]) -> dict[str, str]:
    ids = [uuid.UUID(a) for a in agent_ids if a and a != "_none_"]
    if not ids:
        return {}
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(Agent.id, Agent.hostname).where(Agent.id.in_(ids)))).all()
    return {str(i): h for i, h in rows}


async def run_ioc(client: httpx.AsyncClient, hunt: RetroHunt) -> dict:
    resp = await client.post(f"/{es_client.LOGS_INDEX}/_search",
                             json=ioc_search_body(ioc_query(hunt.ioc_type, hunt.ioc_value, hunt.group_id, hunt.days)))
    resp.raise_for_status()
    body = resp.json()
    total = body.get("hits", {}).get("total", {}).get("value", 0)
    buckets = body.get("aggregations", {}).get("hosts", {}).get("buckets", [])
    names = await _hostnames([b["key"] for b in buckets])
    hosts = []
    for b in buckets:
        samples = [h for h in b["samples"]["hits"]["hits"]]
        groups = b.get("group", {}).get("buckets") or []
        hosts.append({
            "agent_id": None if b["key"] == "_none_" else b["key"],
            "hostname": names.get(b["key"]) or ("syslog / agentless" if b["key"] == "_none_" else b["key"][:8]),
            "group_id": groups[0]["key"] if groups else hunt.group_id,
            "count": b["doc_count"],
            "first_seen": b["first"].get("value_as_string"),
            "last_seen": b["last"].get("value_as_string"),
            "samples": [{"event_id": h["_id"], "log_type": h["_source"].get("log_type"),
                         "created_at": h["_source"].get("created_at"),
                         "line": str(h["_source"].get("raw_message", ""))[:500]} for h in samples],
        })
    alerts = 0
    if hunt.create_alerts:
        for host in hosts:
            if await _alert_ioc(hunt, host):
                alerts += 1
    return {"matched": total, "hosts": len(hosts), "alerts_created": alerts,
            "truncated": len(buckets) >= MAX_HOSTS, "results": {"hosts": hosts}}


async def _alert_ioc(hunt: RetroHunt, host: dict) -> bool:
    from worker.alert_manager import create_alert
    latest = host["samples"][0] if host["samples"] else {}
    rule_match = {
        "id": "retro-hunt", "title": ioc_title(hunt.ioc_type, hunt.ioc_value), "level": "high",
        "description": (f"{hunt.ioc_type} {hunt.ioc_value} appears in {host['count']} stored log lines on "
                        f"{host['hostname']} between {host['first_seen']} and {host['last_seen']} "
                        f"(retro-hunt over {hunt.days} days, trigger: {hunt.trigger})."),
        "tags": ["retro-hunt"], "mitre_tags": [],
    }
    try:
        event_id = uuid.UUID(latest.get("event_id")) if latest.get("event_id") else None
    except ValueError:
        event_id = None
    alert_id = await create_alert(
        rule_match=rule_match, event_id=event_id,
        agent_id=uuid.UUID(host["agent_id"]) if host["agent_id"] else None,
        group_id=host["group_id"] if host["group_id"] != "*" else "default",
        source_ip=hunt.ioc_value if hunt.ioc_type == "ip" else None, hostname=host["hostname"],
    )
    return alert_id is not None


# ─── Rule hunts ──────────────────────────────────────────────────

def log_type_patterns(logsource: dict | None) -> list[str] | None:
    """The log_type globs a rule's logsource covers (None: every log type)."""
    if not has_logsource(logsource):
        return None
    pats = sorted({g for s in SOURCES if logsource_matches(logsource, s) for g in s.log_types})
    if pats:
        return pats
    product, service = (logsource or {}).get("product"), (logsource or {}).get("service")
    return [f"{product}_{service}" if service else f"{product}_*"] if product else None


def rule_query(patterns: list[str] | None, group_id: str, days: int, now: datetime | None = None) -> dict:
    filters: list[dict] = [{"range": {"created_at": {"gte": _since(days, now)}}}]
    if group_id and group_id != "*":
        filters.append({"term": {"group_id": group_id}})
    if patterns:
        filters.append({"bool": {"should": [{"wildcard": {"log_type": p}} for p in patterns],
                                 "minimum_should_match": 1}})
    return {"bool": {"filter": filters}}


def event_view(doc: dict, hostname: str | None) -> dict:
    """The flat event the live pipeline evaluates (consumer._detect)."""
    decoded = doc.get("decoded_fields") or {}
    return {**decoded, "group_id": doc.get("group_id") or "default",
            "hostname": decoded.get("hostname") or hostname or "unknown",
            "raw_message": doc.get("raw_message") or "", "log_type": doc.get("log_type") or ""}


async def run_rule(client: httpx.AsyncClient, hunt: RetroHunt) -> dict:
    import yaml

    from worker.sigma_engine import SigmaEngine
    async with AsyncSessionLocal() as db:
        rule = await db.get(Rule, hunt.rule_id) if hunt.rule_id else None
    if rule is None:
        raise ValueError("the rule no longer exists")
    engine = SigmaEngine()
    engine.load_from_yaml_list([rule.content], rule_ids=[str(rule.id)])
    if engine.load_errors:
        raise ValueError(f"the rule does not compile: {engine.load_errors[0]}")
    doc0 = next((d for d in yaml.safe_load_all(rule.content) if isinstance(d, dict)), {})
    if "correlation" in doc0:
        raise ValueError("correlation rules cannot be retro-hunted; hunt the rules they correlate")
    patterns = log_type_patterns(doc0.get("logsource"))

    pit = (await client.post(f"/{es_client.LOGS_INDEX}/_pit", params={"keep_alive": "2m"})).json()["id"]
    scanned, matches, after = 0, [], None
    names: dict[str, str] = {}
    try:
        while scanned < RULE_MAX_SCANNED and len(matches) < RULE_MAX_MATCHES:
            body = {"size": RULE_PAGE, "query": rule_query(patterns, hunt.group_id, hunt.days),
                    "pit": {"id": pit, "keep_alive": "2m"}, "sort": [{"created_at": "asc"}],
                    "_source": ["raw_message", "decoded_fields", "log_type", "group_id", "agent_id", "created_at"]}
            if after is not None:
                body["search_after"] = after
            resp = await client.post("/_search", json=body)
            resp.raise_for_status()
            data = resp.json()
            pit = data.get("pit_id", pit)
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                break
            missing = [h["_source"].get("agent_id") for h in hits if h["_source"].get("agent_id") not in names]
            names.update(await _hostnames([a for a in set(missing) if a]))
            for h in hits:
                scanned += 1
                src = h["_source"]
                found = await engine.evaluate(event_view(src, names.get(src.get("agent_id") or "")))
                if found:
                    matches.append({"event_id": h["_id"], "created_at": src.get("created_at"),
                                    "agent_id": src.get("agent_id"), "group_id": src.get("group_id"),
                                    "hostname": names.get(src.get("agent_id") or ""), "log_type": src.get("log_type"),
                                    "line": str(src.get("raw_message", ""))[:500]})
                    if len(matches) >= RULE_MAX_MATCHES:
                        break
            after = hits[-1].get("sort")
            if len(hits) < RULE_PAGE:
                break
    finally:
        try:
            await client.request("DELETE", "/_pit", json={"id": pit})
        except Exception:  # noqa: BLE001 — it expires on its own
            pass

    alerts = 0
    if hunt.create_alerts:
        alerts = await _alert_rule_matches(rule, hunt, matches)
    hosts = sorted({m["hostname"] or m["agent_id"] or "unknown" for m in matches})
    truncated = scanned >= RULE_MAX_SCANNED or len(matches) >= RULE_MAX_MATCHES
    return {"scanned": scanned, "matched": len(matches), "hosts": len(hosts), "alerts_created": alerts,
            "truncated": truncated, "results": {"log_types": patterns, "matches": matches[:100], "host_names": hosts}}


async def _alert_rule_matches(rule: Rule, hunt: RetroHunt, matches: list[dict]) -> int:
    """One alert per host, the newest match, titled as the rule's own alert."""
    from worker.alert_manager import create_alert
    newest: dict[str, dict] = {}
    for m in matches:
        key = m["agent_id"] or m["hostname"] or "unknown"
        if key not in newest or (m["created_at"] or "") > (newest[key]["created_at"] or ""):
            newest[key] = m
    made = 0
    for m in newest.values():
        rule_match = {"id": str(rule.id), "rule_db_id": str(rule.id), "title": f"{rule.title} (retro-hunt)",
                      "level": rule.level, "description": f"Found by a retro-hunt of the rule over {hunt.days} days.",
                      "tags": list(rule.tags or []), "mitre_tags": list(rule.mitre_tags or [])}
        alert_id = await create_alert(
            rule_match=rule_match, event_id=uuid.UUID(m["event_id"]) if _is_uuid(m["event_id"]) else None,
            agent_id=uuid.UUID(m["agent_id"]) if _is_uuid(m["agent_id"]) else None,
            group_id=m["group_id"] or "default", source_ip=None, hostname=m["hostname"],
        )
        made += alert_id is not None
    return made


def _is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError):
        return False


# ─── The job loop ────────────────────────────────────────────────

async def run_one(hunt_id: uuid.UUID, client: httpx.AsyncClient | None = None) -> None:
    client = client or es_client._get_client()
    async with AsyncSessionLocal() as db:
        hunt = await db.get(RetroHunt, hunt_id)
        if hunt is None or hunt.status != "pending":
            return
        hunt.status, hunt.started_at = "running", datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(hunt)
    try:
        out = await (run_ioc(client, hunt) if hunt.kind == "ioc" else run_rule(client, hunt))
        values = {"status": "done", **out}
    except Exception as exc:  # noqa: BLE001
        log.warning("retro_hunt_failed", hunt=str(hunt_id), error=str(exc))
        values = {"status": "failed", "error": str(exc)[:1000]}
    async with AsyncSessionLocal() as db:
        await db.execute(update(RetroHunt).where(RetroHunt.id == hunt_id)
                         .values(**values, finished_at=datetime.now(timezone.utc)))
        await db.commit()
    log.info("retro_hunt_finished", hunt=str(hunt_id), kind=hunt.kind, status=values["status"],
             matched=values.get("matched"), alerts=values.get("alerts_created"))


async def retro_hunt_loop() -> None:
    # a hunt a restart interrupted runs again
    async with AsyncSessionLocal() as db:
        await db.execute(update(RetroHunt).where(RetroHunt.status == "running").values(status="pending"))
        await db.commit()
    while True:
        try:
            async with AsyncSessionLocal() as db:
                ids = (await db.execute(select(RetroHunt.id).where(RetroHunt.status == "pending")
                                        .order_by(RetroHunt.created_at).limit(5))).scalars().all()
            for hunt_id in ids:
                await run_one(hunt_id)
        except Exception as exc:  # noqa: BLE001
            log.error("retro_hunt_loop_error", error=str(exc))
        await asyncio.sleep(POLL_SECONDS)
