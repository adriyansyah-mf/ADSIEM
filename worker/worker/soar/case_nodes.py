"""Case evidence and bounded, idempotent IP containment nodes."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import TYPE_CHECKING, Literal, assert_never
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.models import Agent, AgentTask, Case, CaseNote
from worker.soar.case_data import read_case_evidence

if TYPE_CHECKING:
    from worker.soar.nodes import NodeResult


class CaseTrigger(BaseModel):
    model_config = ConfigDict(frozen=True)
    group_id: str
    case_id: UUID | None = None
    alert_id: UUID | None = None


class RunIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID


class CaseContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    trigger: CaseTrigger
    run: RunIdentity


class CaseParams(BaseModel):
    model_config = ConfigDict(frozen=True)
    case_id: UUID
    scope: Literal["event_alert", "case"] = "event_alert"
    hostname: str = ""
    ips: list[str] | str = ""
    duration_seconds: int = Field(default=3600, ge=60, le=604800)
    max_pairs: int = Field(default=100, ge=1, le=100)


class BlockResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    backend: str = ""
    dry_run: bool = False


async def run_case_node(node: dict[str, JsonValue], params: dict[str, JsonValue],
                        ctx: dict[str, JsonValue]) -> "NodeResult":
    from worker.soar.nodes import NodeError, NodeResult

    try:
        context = CaseContext.model_validate(ctx)
        options = CaseParams.model_validate({**params, "case_id": params.get("case_id") or context.trigger.case_id})
    except ValidationError as exc:
        raise NodeError(f"Invalid case node input: {exc}") from exc
    blocking = node["type"] == "case_block_ips"
    async with AsyncSessionLocal() as db:
        query = select(Case).where(Case.id == options.case_id, Case.group_id == context.trigger.group_id)
        if blocking:
            query = query.with_for_update()
        case = (await db.execute(query)).scalar_one_or_none()
        if case is None:
            raise NodeError("Case not found in the run's group")
        if blocking and case.status != "open":
            raise NodeError("Automatic case containment requires an open case")
        snapshot = await read_case_evidence(db, case)
        evidence = [a for a in snapshot.evidence if options.scope == "case" or a.alert_id == context.trigger.alert_id]
        if options.hostname:
            evidence = [a for a in evidence if a.hostname == options.hostname]
        available_ips = {ip for a in evidence for ip in a.ips}
        if not blocking:
            return NodeResult("main", {
                **snapshot.model_dump(mode="json", exclude={"evidence"}),
                "evidence": [a.model_dump(mode="json") for a in evidence], "alert_count": len(evidence),
                "ips": sorted(available_ips), "indicators": sorted({k for a in evidence for k in a.indicators}),
                "hostnames": sorted({a.hostname for a in evidence if a.hostname}),
            })
        match options.ips:
            case str():
                requested = options.ips.replace(",", " ").split()
            case list():
                requested = options.ips
            case unreachable:
                assert_never(unreachable)
        try:
            selected_ips = {str(ip_address(ip)) for ip in requested} if requested else available_ips
        except ValueError as exc:
            raise NodeError("IP selection must contain valid IPv4 or IPv6 literals") from exc
        if not selected_ips <= available_ips:
            raise NodeError("IP selection contains indicators outside the linked evidence")
        pairs = sorted({(a.agent_id, ip) for a in evidence if a.agent_id for ip in a.ips if ip in selected_ips})
        if not pairs:
            raise NodeError("No linked IP/agent pairs in the selected evidence")
        if len(pairs) > options.max_pairs:
            raise NodeError(f"Selection has {len(pairs)} pairs; maximum is {options.max_pairs}")
        agents = (await db.execute(select(Agent).where(
            Agent.id.in_({agent for agent, ip in pairs}), Agent.group_id == case.group_id,
            Agent.approved.is_(True), Agent.status == "online",
        ))).scalars().all()
        if {a.id for a in agents} != {agent for agent, ip in pairs}:
            raise NodeError("Every selected host must be approved, online, and in the case's group")
        previous = (await db.execute(select(AgentTask).where(
            AgentTask.agent_id.in_({a.id for a in agents}), AgentTask.task_type == "block_ip",
            AgentTask.params["case_id"].astext == str(case.id),
        ).order_by(AgentTask.created_at.desc()))).scalars().all()
        task_ids, reused_ids = [], []
        now = datetime.now(timezone.utc)
        for agent_id, ip in pairs:
            existing = None
            for task in previous:
                if task.agent_id != agent_id or task.params.get("ip") != ip:
                    continue
                same_attempt = (task.params.get("soar_run_id") == str(context.run.id)
                                and task.params.get("soar_node_id") == node["id"])
                active = task.status in ("pending", "dispatched", "running")
                try:
                    result = BlockResult.model_validate(task.result or {})
                except ValidationError:
                    result = BlockResult()
                enforced = (task.status == "done" and result.backend in ("nft", "netsh")
                            and not result.dry_run and task.completed_at is not None
                            and task.completed_at + timedelta(seconds=int(task.params.get("duration_seconds", 3600))) > now)
                if same_attempt and task.status == "failed":
                    raise NodeError("The task from this node attempt failed on the agent", {"task_id": str(task.id)})
                if same_attempt and task.status == "done" and not enforced:
                    raise NodeError("The previous task is simulated, unverified, or expired", {"task_id": str(task.id)})
                if same_attempt or active or enforced:
                    existing = task
                    break
            if existing is not None:
                reused_ids.append(str(existing.id))
                continue
            task = AgentTask(agent_id=agent_id, task_type="block_ip", status="pending", params={
                "ip": ip, "duration_seconds": options.duration_seconds, "case_id": str(case.id),
                "soar_run_id": str(context.run.id), "soar_node_id": node["id"],
                "reason": f"SOAR case {case.id}, run {context.run.id}",
            })
            db.add(task)
            await db.flush()
            task_ids.append(str(task.id))
        if task_ids:
            db.add(CaseNote(case_id=case.id, is_ai_generated=True,
                            content=f"SOAR run {context.run.id}: queued {len(task_ids)} IP block tasks; "
                                    f"reused {len(reused_ids)} existing tasks. Await agent execution results."))
        await db.commit()
        return NodeResult("queued", {"case_id": str(case.id), "task_ids": task_ids + reused_ids,
                                     "queued_count": len(task_ids), "reused_count": len(reused_ids),
                                     "execution_status": "check_agent_tasks"})
