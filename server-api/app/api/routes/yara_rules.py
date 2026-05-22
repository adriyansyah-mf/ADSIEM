# server-api/app/api/routes/yara_rules.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Agent, AgentTask, YaraRule
from app.schemas.schemas import YaraRuleCreate, YaraRuleOut, YaraScanRequest, AgentTaskOut

router = APIRouter(prefix="/api/yara-rules", tags=["yara"])

BUILTIN_RULES = [
    {
        "name": "eicar_test",
        "description": "EICAR antivirus test signature",
        "content": "rule eicar_test {\n    meta:\n        description = \"EICAR test file\"\n    strings:\n        $a = \"X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR\"\n    condition:\n        $a\n}",
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
    _=Depends(get_current_user),
):
    r = YaraRule(**body.model_dump())
    db.add(r)
    await db.commit()
    await db.refresh(r)
    return r


@router.put("/{rule_id}", response_model=YaraRuleOut)
async def update_rule(
    rule_id: UUID,
    body: YaraRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    await db.commit()
    await db.refresh(r)
    return r


@router.patch("/{rule_id}/toggle", response_model=YaraRuleOut)
async def toggle_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    await db.execute(update(YaraRule).where(YaraRule.id == rule_id).values(is_enabled=not r.is_enabled))
    await db.commit()
    await db.refresh(r)
    return r


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    r = (await db.execute(select(YaraRule).where(YaraRule.id == rule_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    await db.delete(r)
    await db.commit()


@router.post("/scan", response_model=AgentTaskOut, status_code=201)
async def trigger_scan(
    body: YaraScanRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user=Depends(get_current_user),
):
    agent = (await db.execute(select(Agent).where(Agent.id == body.agent_id))).scalar_one_or_none()
    if not agent:
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
    await db.refresh(task)
    return task


@router.get("/builtins", response_model=list[dict])
async def list_builtins(_=Depends(get_current_user)):
    return BUILTIN_RULES


@router.post("/seed-builtins", status_code=201)
async def seed_builtins(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(get_current_user),
):
    added = 0
    for r in BUILTIN_RULES:
        existing = (await db.execute(select(YaraRule).where(YaraRule.name == r["name"]))).scalar_one_or_none()
        if not existing:
            db.add(YaraRule(**r))
            added += 1
    await db.commit()
    return {"added": added}
