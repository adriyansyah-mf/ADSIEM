# server-api/app/api/routes/yara_rules.py
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group, require_permission
from app.models.models import Agent, AgentTask, User, YaraRule
from app.schemas.schemas import YaraRuleCreate, YaraRuleOut, YaraScanRequest, AgentTaskOut
from app.services import yara_ruleset
from app.services.audit import audit_log

router = APIRouter(prefix="/api/yara-rules", tags=["yara"])

BUILTIN_RULES = [
    {
        "name": "eicar_test",
        "description": "EICAR antivirus test signature",
        "content": "rule eicar_test {\n    meta:\n        description = \"EICAR test file\"\n    strings:\n        $a = \"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR\"\n    condition:\n        $a\n}",
    },
    {
        "name": "crypto_miner",
        "description": "Detects cryptocurrency mining software patterns",
        "content": "rule crypto_miner {\n    meta:\n        description = \"Cryptocurrency miner indicators\"\n    strings:\n        $s1 = \"stratum+tcp://\"\n        $s2 = \"xmrig\"\n        $s3 = \"moneropool\"\n        $s4 = \"nanopool.org\"\n        $s5 = \"supportxmr.com\"\n    condition:\n        any of them\n}",
    },
    {
        "name": "webshell_php",
        "description": "PHP webshell signatures",
        "content": "rule webshell_php {\n    meta:\n        description = \"PHP webshell indicators\"\n    strings:\n        $s1 = \"eval(base64_decode\"\n        $s2 = \"eval(gzinflate\"\n        $s3 = \"passthru($_GET\"\n        $s4 = \"system($_POST\"\n        $s5 = \"shell_exec($_REQUEST\"\n    condition:\n        any of them\n}",
    },
    {
        "name": "reverse_shell_bash",
        "description": "Bash/netcat reverse shell scripts",
        "content": "rule reverse_shell_bash {\n    meta:\n        description = \"Reverse shell indicators in scripts\"\n    strings:\n        $s1 = \"/dev/tcp/\"\n        $s2 = \"bash -i >&\"\n        $s3 = \"nc -e /bin/bash\"\n        $s4 = \"nc -e /bin/sh\"\n        $s5 = \"python -c 'import socket\"\n    condition:\n        any of them\n}",
    },
    {
        "name": "ransomware_extension",
        "description": "Common ransomware file extension markers",
        "content": "rule ransomware_note {\n    meta:\n        description = \"Ransomware note keywords\"\n    strings:\n        $s1 = \"YOUR FILES ARE ENCRYPTED\"\n        $s2 = \"your files have been encrypted\"\n        $s3 = \"HOW TO RECOVER\"\n        $s4 = \"bitcoin\" nocase\n        $s5 = \"README_FOR_DECRYPT\"\n    condition:\n        2 of them\n}",
    },
    {
        "name": "ssh_private_key",
        "description": "SSH private key material in files",
        "content": "rule ssh_private_key {\n    meta:\n        description = \"SSH private key content\"\n    strings:\n        $s1 = \"-----BEGIN RSA PRIVATE KEY-----\"\n        $s2 = \"-----BEGIN EC PRIVATE KEY-----\"\n        $s3 = \"-----BEGIN OPENSSH PRIVATE KEY-----\"\n        $s4 = \"-----BEGIN DSA PRIVATE KEY-----\"\n    condition:\n        any of them\n}",
    },
    {
        "name": "credential_dump",
        "description": "Common credential dumping tool outputs",
        "content": "rule credential_dump {\n    meta:\n        description = \"Credential dumping artifacts\"\n    strings:\n        $s1 = \"SAM\\\\Domains\\\\Account\"\n        $s2 = \"NTLM hash\"\n        $s3 = \"lsadump\"\n        $s4 = \"sekurlsa\"\n        $s5 = \"hashdump\"\n    condition:\n        any of them\n}",
    },
]


@router.get("", response_model=list[YaraRuleOut])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    result = await db.execute(select(YaraRule).order_by(YaraRule.name))
    return result.scalars().all()


@router.post("", response_model=YaraRuleOut, status_code=201)
async def create_rule(
    body: YaraRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("rules:create")),
):
    r = YaraRule(**body.model_dump())
    db.add(r)
    await db.commit()
    yara_ruleset.invalidate()
    await db.refresh(r)
    return r


def _refuse_unvalidated(r: YaraRule) -> None:
    """Enabling a rule deploys it to every agent's on-access scanner. An AI-drafted
    rule gets there only through /activate, after validation and a test scan on
    its current content (services/yara_lifecycle.py)."""
    if r.origin == "ai_draft":
        raise HTTPException(409, "This rule was drafted by AI from case evidence: enable it with Activate, which "
                                 "needs a passing validation and test scan of its current content; until then it "
                                 "stays disabled.")


capability_router = APIRouter(prefix="/api/yara", tags=["yara"])


@capability_router.get("/capabilities")
async def yara_capabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """What the server can do with rules (yaracheck) and which AI drafting mode is in effect."""
    from app.services import yara_capability, yara_drafting
    cap = await yara_capability.capabilities()
    mode, note = await yara_drafting.generation_mode(db)
    return {**cap, "ai_generation_mode": mode, "ai_generation_note": note}


class RuleText(BaseModel):
    content: str = Field(min_length=1, max_length=1_000_000)


class TestTarget(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    path: str = Field(min_length=1, max_length=1024)
    expect: str = Field(pattern="^(match|no_match)$")
    recursive: bool = False


class TestRequest(BaseModel):
    targets: list[TestTarget] = Field(default=[], max_length=10)


class ActivateRequest(BaseModel):
    confirm_fleet_deployment: bool = False


def _capability_error(exc) -> HTTPException:
    return HTTPException(503, f"YARA validation is unavailable: {exc}")


@router.post("/validate")
async def validate_text(
    body: RuleText,
    _=Depends(require_permission("rules:update")),
):
    """Validate any rule text with the agents' engine, plus the drafting quality checks."""
    from app.services import yara_capability, yara_drafting
    try:
        result = await yara_capability.validate(body.content)
    except yara_capability.CapabilityError as exc:
        raise _capability_error(exc)
    return {**result, "quality": yara_drafting.quality(body.content)}


async def _rule(db, rule_id: UUID) -> YaraRule:
    r = await db.get(YaraRule, rule_id)
    if r is None:
        raise HTTPException(404, "Rule not found")
    return r


@router.post("/{rule_id}/validate", response_model=YaraRuleOut)
async def validate_rule(
    rule_id: UUID, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("rules:update"))],
):
    from app.services import yara_capability, yara_lifecycle
    r = await _rule(db, rule_id)
    try:
        r.validation = await yara_lifecycle.validate_rule(r)
    except yara_capability.CapabilityError as exc:
        raise _capability_error(exc)
    await db.commit()
    await db.refresh(r)
    background.add_task(audit_log, db, user.id, "yara_rule_validated", "yara_rule", str(r.id),
                        {"ok": r.validation.get("ok"), "fingerprint": r.validation.get("fingerprint")})
    return r


@router.post("/{rule_id}/test", response_model=YaraRuleOut, status_code=202)
async def test_rule(
    rule_id: UUID, body: TestRequest, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("rules:update"))],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
):
    """Rule-scoped scans on endpoints: the rule (enabled or not) against its sample, which must
    match, and baseline paths an analyst picks, which must not. Live response: agents:manage."""
    from app.services import yara_lifecycle
    if user.role.name != "superadmin" and "agents:manage" not in {p.name for p in user.role.permissions}:
        raise HTTPException(403, "Test scans run on endpoints: they need the agents:manage permission")
    r = await _rule(db, rule_id)
    if not yara_lifecycle.current(r.validation, r) or not r.validation.get("ok"):
        raise HTTPException(409, "Validate the current content before testing it")
    if (r.test_result or {}).get("status") == "running" and yara_lifecycle.current(r.test_result, r):
        raise HTTPException(409, "A test of this content is already running")
    targets = await yara_lifecycle.default_targets(db, r) + [t.model_dump() for t in body.targets]
    if not targets:
        raise HTTPException(422, "Give at least one target (host, path, expect match or no_match)")
    if not any(t["expect"] == "match" for t in targets):
        raise HTTPException(422, "Include at least one target the rule must match (its sample)")
    targets = targets[:yara_lifecycle.MAX_TARGETS]
    r.test_result = {"status": "running", "fingerprint": yara_ruleset.fingerprint(r.content), "at": None,
                     "results": [{**t, "passed": None} for t in targets]}
    await db.commit()
    await db.refresh(r)
    yara_lifecycle.spawn_test(r.id, targets, group_filter, user.id)
    background.add_task(audit_log, db, user.id, "yara_rule_test_started", "yara_rule", str(r.id),
                        {"targets": targets})
    return r


@router.post("/{rule_id}/activate", response_model=YaraRuleOut)
async def activate_rule(
    rule_id: UUID, body: ActivateRequest, background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_permission("rules:update"))],
):
    """Enable an AI-drafted rule: every agent loads it for on-access scanning at its next heartbeat."""
    from app.services import yara_drafting, yara_lifecycle
    r = await _rule(db, rule_id)
    if r.origin != "ai_draft":
        raise HTTPException(409, "Only AI-drafted rules go through activation; enable others with the toggle")
    if r.is_enabled:
        return r
    mode, _ = await yara_drafting.generation_mode(db)
    blockers = yara_lifecycle.activation_blockers(r, mode)
    if blockers:
        raise HTTPException(409, {"message": "this rule cannot be activated yet", "problems": blockers})
    if not body.confirm_fleet_deployment:
        raise HTTPException(422, {"message": "confirm the fleet-wide deployment", "problems": [
            "activating sends this rule to every agent's on-access scanner within one heartbeat; the test scan "
            f"found {r.test_result.get('baseline_matches', 0)} matches on the baseline paths"]})
    r.is_enabled, r.activated_by, r.activated_at = True, user.id, datetime.now(timezone.utc)
    await db.commit()
    yara_ruleset.invalidate()
    await db.refresh(r)
    background.add_task(audit_log, db, user.id, "yara_rule_activated", "yara_rule", str(r.id),
                        {"fingerprint": yara_ruleset.fingerprint(r.content), "draft": str(r.draft_id),
                         "baseline_matches": r.test_result.get("baseline_matches", 0)})
    return r


@router.put("/{rule_id}", response_model=YaraRuleOut)
async def update_rule(
    rule_id: UUID,
    body: YaraRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("rules:update")),
):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    if r.origin == "ai_draft" and r.is_enabled and body.content != r.content:
        raise HTTPException(409, "Disable this AI-drafted rule before changing it: the new content must be "
                                 "validated and tested again before it reaches the agents")
    for k, v in body.model_dump().items():  # name, description, content: enabling is the toggle's job
        setattr(r, k, v)
    await db.commit()
    yara_ruleset.invalidate()
    await db.refresh(r)
    return r


@router.patch("/{rule_id}/toggle", response_model=YaraRuleOut)
async def toggle_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("rules:update")),
):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    if not r.is_enabled:
        _refuse_unvalidated(r)
    await db.execute(update(YaraRule).where(YaraRule.id == rule_id).values(is_enabled=not r.is_enabled))
    await db.commit()
    yara_ruleset.invalidate()
    await db.refresh(r)
    return r


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("rules:delete")),
):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    await db.delete(r)
    await db.commit()
    yara_ruleset.invalidate()


@router.post("/scan", response_model=AgentTaskOut, status_code=201)
async def trigger_scan(
    body: YaraScanRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user=Depends(require_permission("agents:manage")),
    group_filter: str | None = Depends(get_scoped_group),
):
    agent = (await db.execute(select(Agent).where(Agent.id == body.agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(404, "Agent not found")
    if group_filter and agent.group_id != group_filter:
        raise HTTPException(404, "Agent not found")

    if body.rule_ids:
        rules = (await db.execute(select(YaraRule).where(YaraRule.id.in_(body.rule_ids), YaraRule.is_enabled == True))).scalars().all()
    else:
        rules = (await db.execute(select(YaraRule).where(YaraRule.is_enabled == True))).scalars().all()

    if not rules:
        raise HTTPException(400, "No enabled YARA rules found")

    params = {
        "path": body.path,
        "recursive": body.recursive,
        "rules": [{"id": str(r.id), "name": r.name, "content": r.content} for r in rules],
    }
    task = AgentTask(agent_id=body.agent_id, task_type="yara_scan", params=params, created_by=user.id)
    db.add(task)
    await db.commit()
    yara_ruleset.invalidate()
    await db.refresh(task)
    return task


class YaraMemoryScanRequest(BaseModel):
    agent_id: UUID
    pid: int = Field(0, ge=0)  # 0 = every process
    rule_ids: list[UUID] | None = None  # None = all enabled rules


@router.post("/scan-memory", response_model=AgentTaskOut, status_code=201)
async def trigger_memory_scan(
    body: YaraMemoryScanRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user=Depends(require_permission("agents:manage")),
    group_filter: str | None = Depends(get_scoped_group),
):
    """Scan one process's memory (or every process's) with the YARA rules
    (agent task memory_scan, agent/internal/task/memory.go)."""
    agent = await db.get(Agent, body.agent_id)
    if not agent or (group_filter and agent.group_id != group_filter):
        raise HTTPException(404, "Agent not found")
    q = select(YaraRule).where(YaraRule.is_enabled == True)  # noqa: E712
    if body.rule_ids:
        q = q.where(YaraRule.id.in_(body.rule_ids))
    rules = (await db.execute(q)).scalars().all()
    if not rules:
        raise HTTPException(400, "No enabled YARA rules found")
    params = {"pid": body.pid, "rules": [{"id": str(r.id), "name": r.name, "content": r.content} for r in rules]}
    task = AgentTask(agent_id=body.agent_id, task_type="memory_scan", params=params, created_by=user.id)
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return task


@router.get("/builtins", response_model=list[dict])
async def list_builtins(_=Depends(get_current_user)):
    return BUILTIN_RULES


@router.post("/seed-builtins", status_code=201)
async def seed_builtins(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(require_permission("rules:create")),
):
    added = 0
    for r in BUILTIN_RULES:
        existing = (await db.execute(select(YaraRule).where(YaraRule.name == r["name"]))).scalar_one_or_none()
        if not existing:
            db.add(YaraRule(**r))
            added += 1
    await db.commit()
    yara_ruleset.invalidate()
    return {"added": added}


# last: "/{rule_id}" would otherwise catch GET /builtins
@router.get("/{rule_id}", response_model=YaraRuleOut)
async def get_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    return await _rule(db, rule_id)
