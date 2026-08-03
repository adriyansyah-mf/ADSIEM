# server-api/app/api/routes/mitre.py
"""MITRE ATT&CK heatmap — aggregates Alert.mitre_techniques into tactic/technique counts."""
from typing import Annotated
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.core.mitre_tactics import TACTIC_ORDER, parse_technique, tactic_for_code
from app.models.models import Alert

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/heatmap")
async def mitre_heatmap(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=90, le=365),
):
    """Count occurrences of each MITRE technique across alerts in the window,
    grouped by tactic, for an ATT&CK-Navigator-style heatmap."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    q = select(Alert.mitre_techniques).where(
        Alert.created_at >= since,
        Alert.mitre_techniques != [],
    )
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    rows = (await db.execute(q)).scalars().all()

    # code -> {name, tactic, count}
    counts: dict[str, dict] = {}
    total_hits = 0
    for techniques in rows:
        for entry in techniques or []:
            code, name = parse_technique(entry)
            tactic = tactic_for_code(code)
            if tactic == "Unknown":
                continue
            total_hits += 1
            slot = counts.setdefault(code, {"technique_id": code, "technique_name": name, "tactic": tactic, "count": 0})
            slot["count"] += 1
            # Prefer the longest/most descriptive name seen for this code
            if len(name) > len(slot["technique_name"]):
                slot["technique_name"] = name

    by_tactic: dict[str, list[dict]] = {t: [] for t in TACTIC_ORDER}
    for entry in counts.values():
        by_tactic.setdefault(entry["tactic"], []).append(entry)
    for entries in by_tactic.values():
        entries.sort(key=lambda e: e["count"], reverse=True)

    max_count = max((e["count"] for e in counts.values()), default=0)

    return {
        "period_days": days,
        "total_alerts_with_mitre": len(rows),
        "total_technique_hits": total_hits,
        "max_count": max_count,
        "tactics": [{"tactic": t, "techniques": by_tactic.get(t, [])} for t in TACTIC_ORDER],
    }
