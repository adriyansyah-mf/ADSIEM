"""ti_lookup: the chat AI's on-demand threat-intel lookup.

server-api cannot import the worker's TI code (the image ships a fixed set of
worker modules), so the lookup goes over Redis: a job {id, value, group,
requested_at} is pushed on `siem:ti:lookup`, the worker's ti_lookup_loop runs the
aggregator and writes `siem:ti:result:<id>` (10 min TTL). This waits up to
WAIT_SECONDS for it; otherwise the model is told to ask again in a moment, and
the next ask finds the same job (`siem:ti:pending:<sha1>`) instead of queueing
another. Finished results are cached 10 minutes (`siem:ti:cache:<sha1>`) and
recorded as investigation evidence (`ti_result`, deduplicated by content).

The value check mirrors worker/ti_lookup.py (the two packages cannot share code).
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis_client import get_redis
from app.services import investigation_ledger as ledger
from app.services.investigation_chat_actions import ChatCtx

log = structlog.get_logger()

QUEUE = "siem:ti:lookup"
RESULT_PREFIX = "siem:ti:result:"
CACHE_PREFIX = "siem:ti:cache:"
PENDING_PREFIX = "siem:ti:pending:"
TTL = 600
WAIT_SECONDS = 25.0
TURN_RESERVE = 10.0  # of the turn's budget kept for the model's answer
POLL_SECONDS = 0.25
MAX_LOOKUPS = 3
MAX_VALUE = 512
PENDING = {"status": "pending", "note": "ask again in a moment"}

_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)
_URL = re.compile(r"^https?://[^\s/?#]+(?:[/?#]\S*)?$", re.I)


def check_value(value) -> tuple[str, str]:
    """(normalised value, kind) for one public ip, domain, http(s) url or md5/sha1/sha256; else ValueError."""
    if not isinstance(value, str):
        raise ValueError("value must be a string")
    v = value.strip()
    if not v:
        raise ValueError("value is empty")
    if len(v) > MAX_VALUE:
        raise ValueError(f"value is longer than {MAX_VALUE} characters")
    if re.search(r"\s", v):
        raise ValueError("give one IoC (ip, domain, url or hash), not free text")
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise ValueError("private or reserved addresses are not looked up")
        return str(ip), "ip"
    if _HASH.match(v):
        return v.lower(), "hash"
    if _URL.match(v):
        return v, "url"
    if _DOMAIN.match(v):
        return v.lower(), "domain"
    raise ValueError("not an ip, domain, url or md5/sha1/sha256 hash")


def _summary(value: str, result: dict) -> str:
    rep = [r for r in result.get("reputation") or [] if isinstance(r, dict)]
    bad = [r for r in rep if r.get("malicious")]
    head = (f"Threat intel for {value}: overall risk {result.get('overall_risk', 0)}; "
            f"{len(bad)} of {len(rep)} indicator(s) flagged malicious")
    lines = [head, *[f"- {b}" for b in (result.get("provider_bullets") or [])[:10]]]
    return "\n".join(lines)[:4000]


async def _wait(redis, job_id: str) -> dict | None:
    from app.services.investigation_chat import TURN_DEADLINE
    wait = WAIT_SECONDS
    deadline = TURN_DEADLINE.get()
    if deadline is not None:  # leave the model 10 s to write its answer
        wait = min(wait, deadline - time.monotonic() - TURN_RESERVE)
    end = time.monotonic() + max(wait, 0.0)
    while True:
        raw = await redis.get(RESULT_PREFIX + job_id)
        if raw:
            try:
                data = json.loads(raw)
            except ValueError:
                return {"error": "unreadable result from the TI worker"}
            return data if isinstance(data, dict) else {"error": "unreadable result from the TI worker"}
        if time.monotonic() >= end:
            return None
        await asyncio.sleep(POLL_SECONDS)


async def lookup(db: AsyncSession, ctx: ChatCtx, value: str) -> dict:
    try:
        value, kind = check_value(value)
    except ValueError as exc:
        return {"error": str(exc)}
    redis = await get_redis()
    digest = hashlib.sha1(value.encode()).hexdigest()
    cached = await redis.get(CACHE_PREFIX + digest)
    result = None
    if cached:
        try:
            result = json.loads(cached)
        except ValueError:
            result = None
    if result is None:
        job_id = await redis.get(PENDING_PREFIX + digest)
        if not job_id:
            job_id = uuid.uuid4().hex
            await redis.set(PENDING_PREFIX + digest, job_id, ex=TTL)
            await redis.rpush(QUEUE, json.dumps({
                "id": job_id, "value": value, "group": ctx.group_id,
                "requested_at": datetime.now(timezone.utc).isoformat()}))
        result = await _wait(redis, job_id)
        if result is None:
            return dict(PENDING)
        if "error" in result:
            await redis.set(PENDING_PREFIX + digest, "", ex=1)  # let the next ask queue a fresh job
            return {"error": str(result["error"])[:500]}
        await redis.set(CACHE_PREFIX + digest, json.dumps(result), ex=TTL)
    spec = ledger.EvidenceSpec(
        evidence_type="ti_result", source_type="threat_intel", source_id=value,
        title=f"Threat intel: {value}"[:300], summary=_summary(value, result), payload=result,
        entities={"ioc": value, "kind": kind})
    evidence_id = await ledger.record_evidence(db, investigation_id=ctx.inv_id, group_id=ctx.group_id,
                                               action_id=None, spec=spec)
    return {**result, "evidence_id": str(evidence_id)}


def make_tools(db: AsyncSession, ctx: ChatCtx):
    from app.services.investigation_chat import ChatTool

    used = 0

    async def ti_lookup(args: dict) -> dict:
        nonlocal used
        if used >= MAX_LOOKUPS:
            return {"error": f"ti_lookup limit reached ({MAX_LOOKUPS} per message); answer with what you have"}
        used += 1
        return await lookup(db, ctx, args.get("value"))

    return [ChatTool(
        "ti_lookup",
        "Threat-intelligence reputation (VirusTotal, AbuseIPDB, OTX, GreyNoise...) of ONE public IP, domain, "
        "http(s) URL or md5/sha1/sha256 hash. Not for free text or private addresses. May answer "
        "'pending': ask again in a moment. The result is saved as investigation evidence.",
        {"type": "object", "required": ["value"], "properties": {"value": {"type": "string"}}},
        ti_lookup)]
