import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import SoarEdge, SoarNode, SoarWorkflow, User
from app.services.soar_executor import build_snapshot, validate_graph
from app.services.soar_nodes import catalogue

router = APIRouter()


class NodeIn(BaseModel):
    id: Optional[uuid.UUID] = None
    node_type: str
    name: str
    config: dict = {}
    pos_x: float = 0
    pos_y: float = 0


class EdgeIn(BaseModel):
    source_node_id: uuid.UUID
    source_handle: str = "out"
    target_node_id: uuid.UUID


class WorkflowIn(BaseModel):
    name: str
    description: Optional[str] = None
    is_enabled: bool = True
    nodes: list[NodeIn] = []
    edges: list[EdgeIn] = []


def _workflow_out(workflow: SoarWorkflow, nodes: list[SoarNode], edges: list[SoarEdge]) -> dict:
    return {
        "id": str(workflow.id),
        "name": workflow.name,
        "description": workflow.description,
        "is_enabled": workflow.is_enabled,
        "nodes": [
            {
                "id": str(n.id), "node_type": n.node_type, "name": n.name,
                "config": n.config, "pos_x": n.pos_x, "pos_y": n.pos_y,
            }
            for n in nodes
        ],
        "edges": [
            {
                "id": str(e.id), "source_node_id": str(e.source_node_id),
                "source_handle": e.source_handle, "target_node_id": str(e.target_node_id),
            }
            for e in edges
        ],
    }


async def _load_graph(db: AsyncSession, workflow_id: uuid.UUID):
    nodes = (await db.execute(
        select(SoarNode).where(SoarNode.workflow_id == workflow_id)
    )).scalars().all()
    edges = (await db.execute(
        select(SoarEdge).where(SoarEdge.workflow_id == workflow_id)
    )).scalars().all()
    return nodes, edges


async def _require_workflow(db: AsyncSession, workflow_id: uuid.UUID, group_id: Optional[str]):
    workflow = await db.get(SoarWorkflow, workflow_id)
    if workflow is None or (group_id and workflow.group_id != group_id):
        raise HTTPException(status_code=404, detail="Workflow not found")
    return workflow


async def _replace_graph(db: AsyncSession, workflow: SoarWorkflow, body: WorkflowIn) -> None:
    """Rewrite the whole graph, rejecting an invalid graph before anything is persisted."""
    id_map = {node.id or uuid.uuid4(): node for node in body.nodes}
    if len(id_map) != len(body.nodes):
        raise HTTPException(status_code=422, detail="Duplicate node id in request")
    staged_nodes = [
        SoarNode(
            id=node_id, workflow_id=workflow.id, node_type=node.node_type,
            name=node.name, config=node.config, pos_x=node.pos_x, pos_y=node.pos_y,
        )
        for node_id, node in id_map.items()
    ]
    staged_ids = set(id_map)
    for edge in body.edges:
        for endpoint in (edge.source_node_id, edge.target_node_id):
            if endpoint not in staged_ids:
                raise HTTPException(
                    status_code=422,
                    detail=f"Edge references unknown node {endpoint}",
                )
    staged_edges = [
        SoarEdge(
            id=uuid.uuid4(), workflow_id=workflow.id,
            source_node_id=edge.source_node_id, source_handle=edge.source_handle,
            target_node_id=edge.target_node_id,
        )
        for edge in body.edges
    ]
    try:
        validate_graph(build_snapshot(staged_nodes, staged_edges))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"Invalid workflow graph: {error}")

    await db.execute(delete(SoarEdge).where(SoarEdge.workflow_id == workflow.id))
    await db.execute(delete(SoarNode).where(SoarNode.workflow_id == workflow.id))
    for node in staged_nodes:
        db.add(node)
    for edge in staged_edges:
        db.add(edge)


@router.get("/node-types")
async def list_node_types(_: User = Depends(get_current_user)):
    return catalogue()


@router.get("/workflows")
async def list_workflows(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    query = select(SoarWorkflow)
    if group_id:
        query = query.where(SoarWorkflow.group_id == group_id)
    workflows = (await db.execute(query.order_by(SoarWorkflow.created_at.desc()))).scalars().all()
    return [
        {
            "id": str(w.id), "name": w.name, "description": w.description,
            "is_enabled": w.is_enabled,
        }
        for w in workflows
    ]


@router.post("/workflows", status_code=201)
async def create_workflow(
    body: WorkflowIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = SoarWorkflow(
        id=uuid.uuid4(), name=body.name, description=body.description,
        is_enabled=body.is_enabled,
        group_id=group_id or current_user.group_id or "default",
    )
    db.add(workflow)
    await db.flush()
    await _replace_graph(db, workflow, body)
    await db.commit()
    nodes, edges = await _load_graph(db, workflow.id)
    return _workflow_out(workflow, nodes, edges)


@router.get("/workflows/{workflow_id}")
async def get_workflow(
    workflow_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = await _require_workflow(db, workflow_id, group_id)
    nodes, edges = await _load_graph(db, workflow.id)
    return _workflow_out(workflow, nodes, edges)


@router.put("/workflows/{workflow_id}")
async def update_workflow(
    workflow_id: uuid.UUID,
    body: WorkflowIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = await _require_workflow(db, workflow_id, group_id)
    workflow.name = body.name
    workflow.description = body.description
    workflow.is_enabled = body.is_enabled
    await _replace_graph(db, workflow, body)
    await db.commit()
    nodes, edges = await _load_graph(db, workflow.id)
    return _workflow_out(workflow, nodes, edges)


@router.delete("/workflows/{workflow_id}", status_code=204)
async def delete_workflow(
    workflow_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: Optional[str] = Depends(get_scoped_group),
):
    workflow = await _require_workflow(db, workflow_id, group_id)
    await db.delete(workflow)
    await db.commit()
