# server-api/app/services/yara_lifecycle.py
"""Validate → test → activate for YARA rules the AI drafted (spec sections
10.5-10.7, Phase 4). Enabling a rule puts it in every agent's on-access
scanner within a heartbeat, so an AI draft gets there only when:

- it validates with the agents' engine (yaracheck) and has no blocking
  quality problem;
- a rule-scoped test scan on endpoints matched its sample and stayed quiet
  on the baseline paths an analyst chose;
- both results are for its current content (an edit voids them), and a
  person with rules:update confirms the fleet-wide deployment.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.models import Agent, Flow, FlowLog, FlowRowBatch, YaraDraft, YaraRule
from app.services import yara_capability as capability
from app.services import yara_drafting as drafting
from app.services.yara_ruleset import fingerprint

log = structlog.get_logger()

FLOW_WAIT = 300
MAX_TARGETS = 10

_tasks: set[asyncio.Task] = set()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def current(result: dict | None, rule: YaraRule) -> bool:
    """A validation or test result counts only for the content it was made with."""
    return bool(result) and result.get("fingerprint") == fingerprint(rule.content)


async def validate_rule(rule: YaraRule) -> dict:
    """Validate the stored content with yaracheck (and the drafting quality checks)."""
    result = await capability.validate(rule.content)
    q = drafting.quality(rule.content)
    result.update(at=now(), quality=q)
    if result.get("ok") and q["blocking"]:
        result["ok"], result["error"] = False, "blocking quality problems: " + "; ".join(q["blocking"])
    return result


def artifact_for(path: str) -> str:
    return "Windows.Detection.Yara" if re.match(r"^[A-Za-z]:[\\/]|^\\\\", path) else "Linux.Detection.Yara"


async def default_targets(db, rule: YaraRule) -> list[dict]:
    """An AI draft is tested at least against the sample it was drafted from."""
    if rule.draft_id is None:
        return []
    draft = await db.get(YaraDraft, rule.draft_id)
    if draft is None or not draft.host or not draft.path:
        return []
    return [{"host": draft.host, "path": draft.path, "expect": "match", "recursive": False}]


def spawn_test(rule_id: uuid.UUID, targets: list[dict], group_filter: str | None, user_id: uuid.UUID | None) -> None:
    task = asyncio.create_task(run_test(rule_id, targets, group_filter, user_id))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def _scan(target: dict, rule: dict, group_filter: str | None, user_id: uuid.UUID | None) -> dict:
    """One rule-scoped scan on one endpoint; the rule needn't be enabled."""
    from app.api.routes.flows import TERMINAL, schedule_flow
    from app.core.redis_client import get_redis

    out = {**target, "matched": False, "files": [], "error": None, "flow_id": None}
    async with AsyncSessionLocal() as db:
        q = select(Agent).where(Agent.hostname.ilike(target["host"]))
        if group_filter is not None:
            q = q.where(Agent.group_id == group_filter)
        agent = (await db.execute(q)).scalars().first()
        if agent is None:
            out["error"] = f"no agent named {target['host']}"
            return out
        if agent.status != "online":
            out["error"] = f"{agent.hostname} is {agent.status}"
            return out
        flow = await schedule_flow(
            db, await get_redis(), agent_id=agent.id, artifact=artifact_for(target["path"]),
            params={"Path": target["path"], "Recursive": bool(target.get("recursive"))},
            group_filter=agent.group_id, created_by=user_id,
            scheduled_by=f"YARA test of rule {rule['name']} (revision {rule['revision'][:12]})",
            only_rules=[{"id": rule["id"], "name": rule["name"], "content": rule["content"]}],
        )
        flow_id = flow.id
    out["flow_id"] = str(flow_id)
    deadline = asyncio.get_running_loop().time() + FLOW_WAIT
    status = "scheduled"
    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(2)
        async with AsyncSessionLocal() as db:
            status = (await db.execute(select(Flow.status).where(Flow.id == flow_id))).scalar_one()
        if status in TERMINAL:
            break
    async with AsyncSessionLocal() as db:
        rows = [r for (b,) in (await db.execute(select(FlowRowBatch.rows).where(FlowRowBatch.flow_id == flow_id)))
                .all() for r in b]
        errors = [m for (m,) in (await db.execute(select(FlowLog.message).where(
            FlowLog.flow_id == flow_id, FlowLog.level == "error").limit(3))).all()]
    files = sorted({str(r.get("File")) for r in rows if r.get("File")})
    out.update(matched=bool(files), files=files[:20], match_count=len(files))
    if status not in TERMINAL:
        out["error"] = f"the scan is still {status} after {FLOW_WAIT}s"
    elif status != "finished" or errors:
        out["error"] = "; ".join(errors) or f"the scan ended {status}"
    return out


async def run_test(rule_id: uuid.UUID, targets: list[dict], group_filter: str | None,
                   user_id: uuid.UUID | None) -> None:
    async with AsyncSessionLocal() as db:
        rule = await db.get(YaraRule, rule_id)
        snapshot = {"id": str(rule.id), "name": rule.name, "content": rule.content,
                    "revision": fingerprint(rule.content)}
    results = []
    try:
        results = list(await asyncio.gather(*[_scan(t, snapshot, group_filter, user_id) for t in targets]))
        for r in results:
            r["passed"] = r["error"] is None and r["matched"] == (r["expect"] == "match")
        status = "passed" if results and all(r["passed"] for r in results) else "failed"
    except Exception as exc:  # noqa: BLE001 — recorded on the rule
        log.warning("yara_test_failed", rule=str(rule_id), error=str(exc))
        status, results = "failed", results or [{"error": str(exc), "passed": False}]
    async with AsyncSessionLocal() as db:
        rule = await db.get(YaraRule, rule_id)
        if rule is None:
            return
        rule.test_result = {"status": status, "fingerprint": snapshot["revision"], "results": results, "at": now(),
                            "baseline_matches": sum(r.get("match_count", 0) for r in results
                                                    if r.get("expect") == "no_match")}
        await db.commit()


def activation_blockers(rule: YaraRule, mode: str) -> list[str]:
    """Why an AI-drafted rule may not be enabled yet (empty: it may)."""
    out = []
    if mode != "full":
        out.append("yara_ai_generation is not running in full mode (Settings, and the yaracheck capability)")
    if not current(rule.validation, rule):
        out.append("validate the current content first")
    elif not rule.validation.get("ok"):
        out.append(f"the current content does not validate: {rule.validation.get('error')}")
    if not current(rule.test_result, rule):
        out.append("run a test scan on the current content first")
    elif rule.test_result.get("status") != "passed":
        out.append("the last test scan did not pass")
    return out
