# worker/worker/ioc_store.py
"""Persistence for observed indicators of compromise (IOCs) and their links
to alerts/events/rules/cases, so an analyst can pivot from one indicator to
everything it has touched. Raw SQL + ON CONFLICT (matching the style used by
app/services/audit.py's chain-head upsert) rather than the ORM, since this is
a single narrow upsert/link pair, not a full model needing relationships."""
from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

VALID_ENTITY_TYPES = {"event", "alert", "rule", "case"}

# Confidence thresholds for deriving a verdict from a reputation score.
MALICIOUS_THRESHOLD = 0.7
SUSPICIOUS_THRESHOLD = 0.3


def verdict_from_confidence(confidence: float) -> str:
    if confidence >= MALICIOUS_THRESHOLD:
        return "malicious"
    if confidence >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "unknown"


async def upsert_ioc_observation(
    db: AsyncSession,
    *,
    group_id: str,
    indicator: str,
    ioc_type: str,
    confidence: float,
    verdict: str,
    source: str,
    raw_ref: dict[str, Any] | None = None,
) -> uuid.UUID:
    """Insert a new observation, or if one already exists for this
    (group, indicator, type), bump last_seen and keep the higher-confidence
    verdict rather than overwriting -- a later low-confidence lookup should
    not erase an earlier confirmed-malicious verdict."""
    # `id` has no DB-side DEFAULT (the ORM model sets it client-side via
    # default=uuid.uuid4, which this raw-SQL path bypasses), so it must be
    # generated here and included explicitly -- otherwise a fresh INSERT
    # (the no-conflict path) fails on a NOT NULL violation.
    new_id = uuid.uuid4()
    result = await db.execute(
        text(
            """
            INSERT INTO ioc_observations
                (id, group_id, indicator, ioc_type, confidence, verdict, source, first_seen, last_seen, raw_ref)
            VALUES (:id, :group_id, :indicator, :ioc_type, :confidence, :verdict, :source, NOW(), NOW(), CAST(:raw_ref AS JSONB))
            ON CONFLICT (group_id, indicator, ioc_type) DO UPDATE SET
                last_seen = NOW(),
                confidence = GREATEST(ioc_observations.confidence, EXCLUDED.confidence),
                verdict = CASE WHEN EXCLUDED.confidence >= ioc_observations.confidence
                               THEN EXCLUDED.verdict ELSE ioc_observations.verdict END,
                source = EXCLUDED.source,
                raw_ref = COALESCE(EXCLUDED.raw_ref, ioc_observations.raw_ref)
            RETURNING id
            """
        ),
        {
            "id": str(new_id),
            "group_id": group_id,
            "indicator": indicator,
            "ioc_type": ioc_type,
            "confidence": confidence,
            "verdict": verdict,
            "source": source,
            "raw_ref": json.dumps(raw_ref) if raw_ref is not None else None,
        },
    )
    return result.scalar_one()


async def link_ioc(
    db: AsyncSession,
    *,
    ioc_id: uuid.UUID,
    group_id: str,
    entity_type: str,
    entity_id: str,
) -> None:
    if entity_type not in VALID_ENTITY_TYPES:
        raise ValueError(f"invalid entity_type: {entity_type!r}")
    await db.execute(
        text(
            """
            INSERT INTO ioc_links (id, ioc_id, group_id, entity_type, entity_id, linked_at)
            VALUES (:id, :ioc_id, :group_id, :entity_type, :entity_id, NOW())
            ON CONFLICT (ioc_id, entity_type, entity_id) DO NOTHING
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "ioc_id": str(ioc_id),
            "group_id": group_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
        },
    )


async def record_enrichment_iocs(
    db: AsyncSession,
    *,
    group_id: str,
    alert_id: str | None,
    iocs: list[Any],
    reputation: list[Any],
    source: str = "ti_enrichment",
) -> list[uuid.UUID]:
    """Persist every IOC an enrichment pass surfaced and link each one to the
    alert it was found on. Linking is best-effort skipped (not failed) when
    there's no alert yet, e.g. background enrichment without alert context."""
    reputation_by_value = {r.ioc_value: r for r in reputation}
    ids: list[uuid.UUID] = []
    for ioc in iocs:
        score = reputation_by_value.get(ioc.value)
        confidence = score.score if score else 0.0
        ioc_type = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
        ioc_id = await upsert_ioc_observation(
            db,
            group_id=group_id,
            indicator=ioc.value,
            ioc_type=ioc_type,
            confidence=confidence,
            verdict=verdict_from_confidence(confidence),
            source=source,
        )
        ids.append(ioc_id)
        if alert_id:
            await link_ioc(db, ioc_id=ioc_id, group_id=group_id, entity_type="alert", entity_id=alert_id)
    await db.commit()
    return ids
