"""Node handlers. Each takes the node, its rendered params and the run context,
and returns NodeResult(output_name, data) or raises NodeError.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from sqlalchemy import select, update

from worker.database import AsyncSessionLocal
from worker.models import Agent, AgentTask, Alert, AlertNote, AlertSuppression, Case
from worker.soar.conditions import matches
from worker.soar.template import lookup

log = structlog.get_logger()

WAIT = "__wait__"
HTTP_MAX_BYTES = 1_000_000
AI_CONTEXT_CHARS = 6000


class NodeError(Exception):
    def __init__(self, message: str, data: dict | None = None):
        super().__init__(message)
        self.data = data


@dataclass
class NodeResult:
    output: str
    data: Any


def _trigger(ctx: dict) -> dict:
    return ctx.get("trigger") or {}


async def _note(ctx: dict, content: str) -> None:
    alert_id = _trigger(ctx).get("alert_id")
    if not alert_id:
        return
    async with AsyncSessionLocal() as db:
        db.add(AlertNote(alert_id=alert_id, content=content))
        await db.commit()


# ─── Trigger / If ───────────────────────────────────────────────────────────

async def run_trigger(node: dict, params: dict, ctx: dict) -> NodeResult:
    return NodeResult("main", _trigger(ctx))


async def run_if(node: dict, params: dict, ctx: dict) -> NodeResult:
    # Conditions are evaluated from the raw params so values keep their templates.
    ok = matches(node.get("params") or {}, ctx)
    return NodeResult("true" if ok else "false", {"result": ok})


# ─── Enrich ─────────────────────────────────────────────────────────────────

async def run_enrich(node: dict, params: dict, ctx: dict) -> NodeResult:
    indicator = str(params.get("indicator") or _trigger(ctx).get("source_ip") or "").strip()
    if not indicator:
        raise NodeError("no indicator to enrich")
    from worker.ai_analyst import _build_ti_config
    from worker.ti.aggregator import EnrichmentAggregator
    summary = await EnrichmentAggregator(await _build_ti_config()).enrich(indicator)
    data = {"indicator": indicator, "risk": summary.overall_risk, "bullets": list(summary.provider_bullets)}
    if params.get("add_note", True):
        body = "\n".join(f"- {b}" for b in data["bullets"]) or "No significant findings."
        await _note(ctx, f"**SOAR enrichment** for `{indicator}` (risk {data['risk']:.2f}):\n\n{body}")
    return NodeResult("main", data)


# ─── AI Decide ──────────────────────────────────────────────────────────────

_AI_SYSTEM = (
    "You are a SOC analyst deciding one yes/no question inside an automated playbook. "
    "Use only the JSON context given. Reply with JSON only: "
    '{"answer": "yes" or "no", "confidence": 0.0-1.0, "reason": "one or two sentences"}.'
)


async def run_ai_decide(node: dict, params: dict, ctx: dict) -> NodeResult:
    from worker.llm_gateway import LLMError, complete, extract_json
    context = json.dumps({"trigger": ctx.get("trigger"), "steps": ctx.get("steps")}, default=str)[:AI_CONTEXT_CHARS]
    messages = [
        {"role": "system", "content": _AI_SYSTEM},
        {"role": "user", "content": f"Question: {params.get('question')}\n\nContext:\n{context}"},
    ]
    try:
        reply = await complete(messages, temperature=0.0, max_tokens=400)
    except LLMError as exc:
        raise NodeError(f"AI unavailable: {exc}") from None
    parsed = extract_json(reply.text) or {}
    answer = str(parsed.get("answer", "")).strip().lower()
    if answer not in ("yes", "no"):
        raise NodeError("AI reply had no yes/no answer", {"raw": reply.text[:500]})
    try:
        confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0))))
    except (TypeError, ValueError):
        confidence = 0.0
    data = {"answer": answer, "confidence": confidence, "reason": str(parsed.get("reason", ""))[:1000],
            "model": reply.model_used}
    min_conf = float(params.get("min_confidence", 0.6))
    return NodeResult("yes" if answer == "yes" and confidence >= min_conf else "no", data)


# ─── Approval ───────────────────────────────────────────────────────────────

async def run_approval(node: dict, params: dict, ctx: dict) -> NodeResult:
    data = {"message": str(params.get("message") or "Approve this step?"),
            "timeout_minutes": int(params.get("timeout_minutes", 60))}
    await _note(ctx, f"**SOAR approval needed** — {data['message']} (playbook run {ctx['run']['id']})")
    return NodeResult(WAIT, data)


# ─── Response (agent tasks) ─────────────────────────────────────────────────

def _valid_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


async def run_response(node: dict, params: dict, ctx: dict) -> NodeResult:
    op = params["operation"]
    hostname = str(params.get("hostname") or _trigger(ctx).get("hostname") or "").strip()
    group_id = _trigger(ctx).get("group_id", "default")
    if not hostname:
        raise NodeError("no hostname: set one on the node or trigger from an alert that has a host")

    task_params: dict[str, Any] = {}
    if op in ("block_ip", "unblock_ip"):
        ip = _valid_ip(params.get("ip") or _trigger(ctx).get("source_ip"))
        if not ip:
            raise NodeError(f"not a valid IP address: {str(params.get('ip'))[:64]!r}")
        task_params = {"ip": ip, "reason": f"SOAR run {ctx['run']['id']}"}
        if op == "block_ip":
            try:
                duration = int(params.get("duration_seconds", 3600))
            except (TypeError, ValueError):
                duration = 3600
            task_params["duration_seconds"] = duration if duration > 0 else 3600
    elif op == "kill_process":
        try:
            task_params = {"pid": int(params.get("pid")), "force": bool(params.get("force", False))}
        except (TypeError, ValueError):
            raise NodeError(f"pid must be a number, got {params.get('pid')!r}") from None
    elif op == "quarantine_file":
        path = str(params.get("path") or "").strip()
        if not path:
            raise NodeError("path is required")
        task_params = {"path": path}

    return await _queue_agent_task(ctx, hostname, group_id, op, task_params)


async def _queue_agent_task(ctx: dict, hostname: str, group_id: str, op: str, task_params: dict) -> NodeResult:
    """Queue a task for the newest online agent with this hostname in the run's group."""
    async with AsyncSessionLocal() as db:
        agent = (await db.execute(
            select(Agent)
            .where(Agent.hostname == hostname, Agent.status == "online", Agent.group_id == group_id)
            .order_by(Agent.last_seen_at.desc().nullslast())
            .limit(1)
        )).scalar_one_or_none()
        if not agent:
            raise NodeError(f"no online agent named {hostname!r} in group {group_id!r}")
        task = AgentTask(agent_id=agent.id, task_type=op, params=task_params, status="pending")
        db.add(task)
        if op in ("isolate_host", "unisolate_host"):
            await db.execute(update(Agent).where(Agent.id == agent.id).values(is_isolated=op == "isolate_host"))
        await db.commit()
        task_id = str(task.id)

    await _note(ctx, f"**SOAR {op}** queued on `{hostname}` {json.dumps(task_params) if task_params else ''}".strip())
    return NodeResult("main", {"task_id": task_id, "agent_id": str(agent.id), "hostname": hostname,
                               "operation": op, "params": task_params})


# ─── Case & Alert ───────────────────────────────────────────────────────────

async def run_case(node: dict, params: dict, ctx: dict) -> NodeResult:
    op = params["operation"]
    trig = _trigger(ctx)
    alert_id = trig.get("alert_id")
    group_id = trig.get("group_id", "default")

    if op == "create_case":
        async with AsyncSessionLocal() as db:
            if alert_id:
                existing = (await db.execute(select(Case).where(Case.alert_id == alert_id).limit(1))).scalar_one_or_none()
                if existing:
                    return NodeResult("main", {"case_id": str(existing.id), "created": False})
            case = Case(title=str(params.get("title") or f"SOAR: {trig.get('rule_title', 'alert')}")[:255],
                        description=str(params.get("description") or ""),
                        severity=str(params.get("severity") or trig.get("severity") or "medium"),
                        status="open", alert_id=alert_id, group_id=group_id, created_by_ai=False)
            db.add(case)
            await db.commit()
            return NodeResult("main", {"case_id": str(case.id), "created": True})

    if op == "suppress":
        entity_type = params.get("entity_type", "ip")
        value = params.get("value") or {"ip": trig.get("source_ip"), "hostname": trig.get("hostname"),
                                        "rule_title": trig.get("rule_title")}.get(entity_type)
        if not value:
            raise NodeError(f"nothing to suppress: alert has no {entity_type}")
        async with AsyncSessionLocal() as db:
            db.add(AlertSuppression(entity_type=entity_type, entity_value=str(value)[:255],
                                    reason=str(params.get("reason") or "Automated SOAR suppression"),
                                    group_id=group_id, is_active=True))
            await db.commit()
        return NodeResult("main", {"entity_type": entity_type, "value": value})

    if not alert_id:
        raise NodeError(f"{op} needs an alert; this run has none")
    if op == "add_note":
        content = str(params.get("content") or "").strip()
        if not content:
            raise NodeError("note content is empty")
        await _note(ctx, content)
        return NodeResult("main", {"alert_id": alert_id})
    if op == "set_alert_status":
        async with AsyncSessionLocal() as db:
            await db.execute(update(Alert).where(Alert.id == alert_id).values(status=params["status"]))
            await db.commit()
        return NodeResult("main", {"alert_id": alert_id, "status": params["status"]})
    raise NodeError(f"unknown operation {op}")


# ─── Outbound HTTP (HTTP Request + Notify) ──────────────────────────────────

def _allowlist(raw: str) -> tuple[set[str], list]:
    hosts, nets = set(), []
    for item in raw.replace("\n", ",").split(","):
        item = item.strip().lower()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            hosts.add(item)
    return hosts, nets


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _effective_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """The IPv4 address an IPv6 one stands for (IPv4-mapped, NAT64 well-known prefix, 6to4), else itself.

    On DNS64/NAT64 networks every public IPv4 host resolves to 64:ff9b::a.b.c.d,
    which Python counts as non-global; judge the embedded IPv4 instead.
    """
    if ip.version == 6:
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.sixtofour:
            return ip.sixtofour
    return ip


async def check_target(url: str, allowlist_raw: str = "") -> str | None:
    """None if url may be called, else the reason it may not.

    Public addresses are fine. Private ones need the host or a covering CIDR in
    the soar_http_allowlist setting. Loopback, link-local (cloud metadata) and
    unspecified addresses are never allowed.
    """
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        return f"scheme {parsed.scheme!r} not allowed (http or https only)"
    host = (parsed.hostname or "").lower()
    if not host:
        return "URL has no host"
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return f"cannot resolve host {host!r}"
    hosts, nets = _allowlist(allowlist_raw)
    allow_private = os.environ.get("ALLOW_PRIVATE_WEBHOOK_TARGETS", "false").lower() in ("1", "true", "yes")
    for *_, sockaddr in infos:
        ip = _effective_ip(ipaddress.ip_address(sockaddr[0].split("%", 1)[0]))
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return f"{host} resolves to {ip}, which is never allowed"
        if ip.is_private or ip.is_reserved:
            if allow_private or host in hosts or any(ip in n for n in nets):
                continue
            return f"{host} resolves to internal address {ip}; add it to the soar_http_allowlist setting"
    return None


def _parse_body(raw: bytes, content_type: str) -> Any:
    text = raw.decode("utf-8", errors="replace")
    if "json" in content_type or text.lstrip()[:1] in ("{", "["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return text


async def _send(method: str, url: str, *, headers: dict, query: dict, body_type: str, body: Any,
                timeout: float) -> dict:
    from worker.settings_cache import get_setting
    reason = await check_target(url, await get_setting("soar_http_allowlist"))
    if reason:
        raise NodeError(f"blocked: {reason}")
    kwargs: dict[str, Any] = {"headers": {str(k).strip(): str(v).strip() for k, v in headers.items() if str(k).strip()},
                              "params": {str(k): str(v) for k, v in query.items()}}
    if body_type == "json":
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                raise NodeError("body is not valid JSON") from None
        kwargs["json"] = body
    elif body_type == "form":
        kwargs["data"] = {str(k): str(v) for k, v in (body or {}).items()} if isinstance(body, dict) else str(body)
    elif body_type == "text":
        kwargs["content"] = "" if body is None else str(body)

    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            async with client.stream(method, url, **kwargs) as resp:
                chunks, size, truncated = [], 0, False
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > HTTP_MAX_BYTES:
                        chunks.append(chunk[: HTTP_MAX_BYTES - (size - len(chunk))])
                        truncated = True
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks)
                return {
                    "status": resp.status_code,
                    "ok": resp.status_code < 400,
                    "headers": {k.lower(): v for k, v in list(resp.headers.items())[:50]},
                    "body": _parse_body(raw, resp.headers.get("content-type", "")),
                    "truncated": truncated,
                    "elapsed_ms": int((loop.time() - started) * 1000),
                }
    except httpx.TimeoutException:
        raise NodeError(f"timed out after {timeout:g}s") from None
    except httpx.HTTPError as exc:
        raise NodeError(f"request failed: {exc.__class__.__name__}: {exc}") from None


async def run_http(node: dict, params: dict, ctx: dict) -> NodeResult:
    method = str(params.get("method", "GET")).upper()
    timeout = max(1.0, min(float(params.get("timeout", 15)), 30.0))
    data = await _send(method, str(params["url"]).strip(), headers=params.get("headers") or {},
                       query=params.get("query") or {}, body_type=params.get("body_type", "none"),
                       body=params.get("body"), timeout=timeout)
    data["data"] = {name: lookup({"steps": {"_": data}}, f"steps._.{path}")
                    for name, path in (params.get("extract") or {}).items()}
    if not data["ok"] and params.get("fail_on_status", True):
        raise NodeError(f"HTTP {data['status']}", data)
    return NodeResult("main", data)


async def run_notify(node: dict, params: dict, ctx: dict) -> NodeResult:
    channel = params.get("channel", "webhook")
    message = str(params.get("message") or f"SOAR: {_trigger(ctx).get('rule_title', '')}")
    if channel == "discord":
        payload = {"content": message[:2000]}
    elif channel == "slack":
        payload = {"text": message}
    else:
        trig = _trigger(ctx)
        payload = {"event": "soar_notify", "message": message, "run_id": ctx["run"]["id"],
                   "playbook": ctx["run"].get("playbook_name"),
                   "alert": {k: trig.get(k) for k in ("alert_id", "rule_title", "severity", "source_ip",
                                                       "hostname", "user_name", "ai_verdict")}}
    data = await _send("POST", str(params["url"]).strip(), headers={}, query={}, body_type="json",
                       body=payload, timeout=10.0)
    if not data["ok"]:
        raise NodeError(f"HTTP {data['status']}", {"status": data["status"]})
    return NodeResult("main", {"status": data["status"]})


# ─── Investigation: Alert Event / Log Search ────────────────────────────────

LOG_SEARCH_SAMPLE = 5


async def _es_search(query: dict, size: int, sort: list | None = None) -> list[dict]:
    from worker.es_client import search
    try:
        return await search(query, size=size, sort=sort)
    except Exception as exc:  # ES down or query rejected: a node error, not a crash
        raise NodeError(f"log search failed: {exc}") from None


async def _es_count(query: dict) -> int:
    from worker.es_client import LOGS_INDEX, _get_client
    try:
        resp = await _get_client().post(f"/{LOGS_INDEX}/_count", json={"query": query})
        resp.raise_for_status()
        return int(resp.json().get("count", 0))
    except Exception as exc:
        raise NodeError(f"log count failed: {exc}") from None


async def run_alert_event(node: dict, params: dict, ctx: dict) -> NodeResult:
    """The log line that raised the alert, with every decoded field, so later
    nodes can act on what the rule saw: {{ steps.<id>.fields.ProcessId }}."""
    alert_id = str(params.get("alert_id") or _trigger(ctx).get("alert_id") or "").strip()
    if not alert_id:
        raise NodeError("this run has no alert")
    group_id = _trigger(ctx).get("group_id", "default")
    async with AsyncSessionLocal() as db:
        alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if alert is None or (alert.group_id and alert.group_id != group_id):
        raise NodeError(f"alert {alert_id} not found")
    if not alert.event_id:
        raise NodeError("the alert has no source event (correlation or UEBA alert)")
    hits = await _es_search({"bool": {"filter": [{"ids": {"values": [str(alert.event_id)]}},
                                                 {"term": {"group_id": group_id}}]}}, size=1)
    if not hits:
        raise NodeError(f"source event {alert.event_id} is no longer in the log index")
    doc = hits[0]
    fields = doc.get("decoded_fields") or {}
    return NodeResult("main", {
        "event_id": str(alert.event_id), "log_type": doc.get("log_type"), "agent_id": doc.get("agent_id"),
        "created_at": doc.get("created_at"), "raw_message": str(doc.get("raw_message") or "")[:4000],
        "fields": fields,
        # the handful most playbooks need, whatever the source's field vocabulary
        "pid": fields.get("ProcessId") or fields.get("process.pid"),
        "process": fields.get("Image") or fields.get("process.executable") or fields.get("process.name"),
        "command_line": fields.get("CommandLine") or fields.get("process.command_line"),
        "file_path": fields.get("TargetFilename") or fields.get("file.path"),
        "sha256": fields.get("sha256") or fields.get("file.hash.sha256") or fields.get("hash.sha256"),
    })


async def run_log_search(node: dict, params: dict, ctx: dict) -> NodeResult:
    """Count logs in the run's group that match a value over the last N minutes."""
    field = params.get("field", "source_ip")
    value = str(params.get("value") or "").strip()
    if not value:
        raise NodeError("nothing to search for: value rendered empty")
    minutes = max(1, min(int(params.get("minutes", 60)), 7 * 24 * 60))
    group_id = _trigger(ctx).get("group_id", "default")
    filters: list[dict] = [{"term": {"group_id": group_id}},
                           {"range": {"created_at": {"gte": f"now-{minutes}m"}}}]
    if field == "text":
        filters.append({"match_phrase": {"raw_message": value}})
    elif field == "hostname":
        async with AsyncSessionLocal() as db:
            ids = [str(i) for i in (await db.execute(
                select(Agent.id).where(Agent.hostname == value, Agent.group_id == group_id))).scalars().all()]
        if not ids:
            return NodeResult("main", {"count": 0, "field": field, "value": value, "minutes": minutes, "hits": []})
        filters.append({"terms": {"agent_id": ids}})
    else:
        filters.append({"term": {field: value}})
    log_type = str(params.get("log_type") or "").strip()
    if log_type:
        filters.append({"term": {"log_type": log_type}})
    query = {"bool": {"filter": filters}}
    count = await _es_count(query)
    sample = await _es_search(query, size=LOG_SEARCH_SAMPLE, sort=[{"created_at": "desc"}]) if count else []
    return NodeResult("main", {
        "count": count, "field": field, "value": value, "minutes": minutes,
        "hits": [{"created_at": h.get("created_at"), "log_type": h.get("log_type"),
                  "raw_message": str(h.get("raw_message") or "")[:500]} for h in sample],
    })


# ─── Endpoint Scan ──────────────────────────────────────────────────────────

async def run_scan(node: dict, params: dict, ctx: dict) -> NodeResult:
    op = params["operation"]
    hostname = str(params.get("hostname") or _trigger(ctx).get("hostname") or "").strip()
    if not hostname:
        raise NodeError("no hostname: set one on the node or trigger from an alert that has a host")
    task_params: dict[str, Any] = {}
    if op == "file_scan":
        kind = params.get("kind", "quick")
        task_params = {"kind": kind}
        if kind == "paths":
            paths = [p.strip() for p in str(params.get("paths") or "").replace(",", "\n").splitlines() if p.strip()]
            if not paths:
                raise NodeError("paths rendered empty")
            task_params["paths"] = paths
    elif op == "yara_scan":
        path = str(params.get("path") or "").strip()
        if not path:
            raise NodeError("path rendered empty")
        task_params = {"path": path, "recursive": bool(params.get("recursive", True))}
    elif op == "memory_scan":
        raw = str(params.get("pid") or "").strip()
        try:
            task_params = {"pid": int(raw) if raw else 0}  # 0 = every process
        except ValueError:
            raise NodeError(f"pid must be a number, got {raw[:32]!r}") from None
    return await _queue_agent_task(ctx, hostname, _trigger(ctx).get("group_id", "default"), op, task_params)


# ─── Threat Hunt ────────────────────────────────────────────────────────────

async def run_hunt(node: dict, params: dict, ctx: dict) -> NodeResult:
    from worker.models import ThreatHunt
    ioc_type = params.get("ioc_type", "ip")
    value = str(params.get("ioc_value") or "").strip()
    if not value:
        raise NodeError("ioc_value rendered empty")
    if ioc_type == "ip" and not _valid_ip(value):
        raise NodeError(f"not a valid IP address: {value[:64]!r}")
    group_id = _trigger(ctx).get("group_id", "default")
    async with AsyncSessionLocal() as db:
        hunt = ThreatHunt(ioc_type=ioc_type, ioc_value=value[:500], status="pending", group_id=group_id)
        db.add(hunt)
        await db.commit()
        hunt_id = str(hunt.id)
    await _note(ctx, f"**SOAR threat hunt** started for {ioc_type} `{value}` (hunt {hunt_id})")
    return NodeResult("main", {"hunt_id": hunt_id, "ioc_type": ioc_type, "ioc_value": value})


# ─── Block IOC (fleet-wide) ─────────────────────────────────────────────────

async def run_block_ioc(node: dict, params: dict, ctx: dict) -> NodeResult:
    """Fleet-wide, unlike Response: every agent gets the hash or rule on its next sync."""
    from sqlalchemy import text
    from worker import malware_hashes
    op = params["operation"]
    value = str(params.get("value") or "").strip()
    if not value:
        raise NodeError("value rendered empty")
    run_id = str(ctx["run"]["id"])
    label = str(params.get("label") or _trigger(ctx).get("rule_title") or "SOAR")[:64]

    if op == "malware_hash":
        sha = malware_hashes.clean_sha256(value)
        if not sha:
            raise NodeError(f"not a SHA-256: {value[:80]!r}")
        async with AsyncSessionLocal() as db:
            res = await malware_hashes.upsert(db, [{"sha256": sha, "label": label, "reference": f"SOAR run {run_id}"}],
                                              source="analyst", revive_allowed=False)
        await _note(ctx, f"**SOAR block IOC**: SHA-256 `{sha}` added to known malware")
        return NodeResult("main", {"operation": op, "value": sha, "added": bool(res["added"])})

    rule_type = params.get("rule_type", "hash")
    action = params.get("action", "block")
    if rule_type == "hash":
        value = malware_hashes.clean_sha256(value) or ""
        if not value:
            raise NodeError("hash rules need a SHA-256")
    elif not value.startswith("/"):
        raise NodeError(f"{rule_type} rules need an absolute path")
    name = f"SOAR {rule_type} {value}"[:255]
    async with AsyncSessionLocal() as db:
        res = await db.execute(text("""
            INSERT INTO exec_prevention_rules (id, name, description, rule_type, value, parent, action, is_enabled, created_at)
            VALUES (gen_random_uuid(), :name, :desc, :rule_type, :value, '', :action, true, now())
            ON CONFLICT (name) DO NOTHING
            RETURNING id
        """), {"name": name, "desc": f"Added by SOAR run {run_id}: {label}", "rule_type": rule_type,
               "value": value, "action": action})
        rule_id = res.scalar_one_or_none()
        await db.commit()
    await _note(ctx, f"**SOAR block IOC**: execution {action} rule for {rule_type} `{value}`"
                     f"{'' if rule_id else ' (already existed)'}")
    return NodeResult("main", {"operation": op, "value": value, "rule_type": rule_type, "action": action,
                               "rule_id": str(rule_id) if rule_id else None, "added": rule_id is not None})


HANDLERS = {
    "trigger": run_trigger,
    "alert_event": run_alert_event,
    "log_search": run_log_search,
    "scan": run_scan,
    "hunt": run_hunt,
    "block_ioc": run_block_ioc,
    "if": run_if,
    "enrich": run_enrich,
    "ai_decide": run_ai_decide,
    "approval": run_approval,
    "response": run_response,
    "case": run_case,
    "notify": run_notify,
    "http": run_http,
}
