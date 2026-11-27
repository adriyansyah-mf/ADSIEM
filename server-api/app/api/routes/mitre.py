# server-api/app/api/routes/mitre.py
"""MITRE ATT&CK heatmap — aggregates Alert.mitre_techniques into tactic/technique counts."""
import re
from typing import Annotated
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.core.mitre_names import technique_info
from app.core.mitre_tactics import TACTIC_ORDER, parse_technique, tactic_for_code
from app.models.models import Alert, Rule

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


_TECH = re.compile(r"t\d{4}(?:\.\d{3})?", re.IGNORECASE)
_TACTIC_SLUG = {t.lower().replace(" & ", "_and_").replace(" ", "_"): t for t in TACTIC_ORDER}


def _rule_techniques(tags: list[str] | None) -> tuple[set[str], str | None]:
    """Sigma tags ('attack.t1059.001', 'attack.execution') -> technique codes, first tactic named."""
    codes: set[str] = set()
    tactic = None
    for tag in tags or []:
        value = str(tag).lower().removeprefix("attack.")
        if _TECH.fullmatch(value):
            codes.add(value.upper())
        elif tactic is None and value in _TACTIC_SLUG:
            tactic = _TACTIC_SLUG[value]
    return codes, tactic


@router.get("/coverage")
async def mitre_coverage(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(get_current_user),
    days: int = Query(default=30, ge=1, le=365),
):
    """Detection coverage per technique: enabled rules that map to it, and detections in the window."""
    rules_q = select(Rule.mitre_tags, Rule.is_enabled)
    if group_filter:
        rules_q = rules_q.where(Rule.group_id == group_filter)
    rules = (await db.execute(rules_q)).all()

    since = datetime.now(timezone.utc) - timedelta(days=days)
    alerts_q = select(Alert.mitre_techniques).where(Alert.created_at >= since, Alert.mitre_techniques != [])
    if group_filter:
        alerts_q = alerts_q.where(Alert.group_id == group_filter)
    seen: dict[str, int] = {}
    for techniques in (await db.execute(alerts_q)).scalars().all():
        for entry in techniques or []:
            match = _TECH.search(parse_technique(entry)[0])
            if match:
                code = match.group(0).upper()
                seen[code] = seen.get(code, 0) + 1

    cells: dict[str, dict] = {}
    disabled = 0

    def cell(code: str, tactic_hint: str | None) -> dict:
        if code not in cells:
            tactic = tactic_for_code(code)
            cells[code] = {"technique_id": code, "technique_name": technique_info(code)["name"] or code,
                           "tactic": tactic if tactic != "Unknown" else (tactic_hint or "Unknown"),
                           "rules": 0, "detections": 0}
        return cells[code]

    for tags, enabled in rules:
        codes, tactic = _rule_techniques(tags)
        if not enabled:
            disabled += len(codes)
            continue
        for code in codes:
            cell(code, tactic)["rules"] += 1
    for code, count in seen.items():
        cell(code, None)["detections"] = count

    by_tactic: dict[str, list[dict]] = {t: [] for t in TACTIC_ORDER}
    for entry in cells.values():
        if entry["tactic"] in by_tactic:
            by_tactic[entry["tactic"]].append(entry)
    for entries in by_tactic.values():
        entries.sort(key=lambda e: (-e["rules"], -e["detections"], e["technique_id"]))

    return {
        "period_days": days,
        "techniques_total": len(cells),
        "techniques_covered": sum(1 for e in cells.values() if e["rules"] > 0),
        "techniques_detected": sum(1 for e in cells.values() if e["detections"] > 0),
        "detected_without_rule": sum(1 for e in cells.values() if e["detections"] > 0 and e["rules"] == 0),
        "disabled_rule_mappings": disabled,
        "tactics": [{"tactic": t, "techniques": by_tactic[t]} for t in TACTIC_ORDER],
    }
