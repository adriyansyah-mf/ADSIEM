# worker/worker/ueba/trainer.py
import asyncio
import structlog
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, delete, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from worker.database import AsyncSessionLocal
from worker.models import UebaEntityScore, UebaFeatureSnapshot
from worker.ueba.explain import MIN_ENTITY_SNAPSHOTS, build_baseline
from worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS,
    build_user_vector_dict, build_ip_vector_dict,
    vector_from_dict,
)
from worker.ueba.model_codec import dumps_model

log = structlog.get_logger()

MIN_SNAPSHOTS = 50
MODEL_TTL = 7200  # 2 hours — trainer rewrites every hour


async def take_snapshots(redis) -> None:
    """Read active entities from Redis, build feature dicts, upsert hourly snapshot to DB."""
    now = datetime.now(timezone.utc)
    snapshot_hour = now.replace(minute=0, second=0, microsecond=0)

    users = await redis.smembers("ueba:active:users")
    ips   = await redis.smembers("ueba:active:ips")

    async with AsyncSessionLocal() as db:
        for user in users:
            login  = int(await redis.get(f"ueba:u:{user}:login")  or 0)
            failed = int(await redis.get(f"ueba:u:{user}:failed") or 0)
            feat = await build_user_vector_dict(redis, user, login, failed)
            stmt = pg_insert(UebaFeatureSnapshot).values(
                entity_type="user", entity_value=user, group_id="default",
                features=feat, snapshot_hour=snapshot_hour,
            ).on_conflict_do_update(
                index_elements=["entity_type", "entity_value", "group_id", "snapshot_hour"],
                set_={"features": feat},
            )
            await db.execute(stmt)

        for ip in ips:
            total  = int(await redis.get(f"ueba:ip:{ip}:total")  or 0)
            failed = int(await redis.get(f"ueba:ip:{ip}:failed") or 0)
            feat = await build_ip_vector_dict(redis, ip, total, failed)
            stmt = pg_insert(UebaFeatureSnapshot).values(
                entity_type="ip", entity_value=ip, group_id="default",
                features=feat, snapshot_hour=snapshot_hour,
            ).on_conflict_do_update(
                index_elements=["entity_type", "entity_value", "group_id", "snapshot_hour"],
                set_={"features": feat},
            )
            await db.execute(stmt)

        # Prune snapshots older than 8 days
        cutoff = now - timedelta(days=8)
        await db.execute(
            delete(UebaFeatureSnapshot).where(UebaFeatureSnapshot.snapshot_hour < cutoff)
        )
        await db.commit()

    log.info("ueba_snapshots_saved", users=len(users), ips=len(ips))


async def _store_entity_profiles(entity_type: str, rows, keys: list[str]) -> None:
    """Per-entity baselines (from that entity's own hourly snapshots) so an
    anomaly can be explained against the entity's normal, not just everyone's."""
    by_entity: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_entity[r.entity_value].append(r.features)
    profiles = {
        value: build_baseline(feats, keys)
        for value, feats in by_entity.items()
        if len(feats) >= MIN_ENTITY_SNAPSHOTS
    }
    if not profiles:
        return
    async with AsyncSessionLocal() as db:
        for value, profile in profiles.items():
            await db.execute(
                update(UebaEntityScore)
                .where(UebaEntityScore.entity_type == entity_type, UebaEntityScore.entity_value == value)
                .values(feature_profile=profile)
            )
        await db.commit()
    log.info("ueba_entity_profiles_saved", entity_type=entity_type, n=len(profiles))


async def train_models(redis) -> None:
    """Load DB snapshots, train IsolationForest, persist model state to Redis."""
    import numpy as np
    from sklearn.ensemble import IsolationForest

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)

    async with AsyncSessionLocal() as db:
        user_rows = (await db.execute(
            select(UebaFeatureSnapshot)
            .where(UebaFeatureSnapshot.entity_type == "user")
            .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
        )).scalars().all()

        ip_rows = (await db.execute(
            select(UebaFeatureSnapshot)
            .where(UebaFeatureSnapshot.entity_type == "ip")
            .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
        )).scalars().all()

    trained_any = False
    trained_at = datetime.now(timezone.utc).isoformat()

    for entity_type, rows, keys, model_key in [
        ("user", user_rows, USER_FEATURE_KEYS, "ueba:model:user"),
        ("ip",   ip_rows,   IP_FEATURE_KEYS,   "ueba:model:ip"),
    ]:
        if len(rows) < MIN_SNAPSHOTS:
            log.info("ueba_cold_start", entity_type=entity_type, n=len(rows), needed=MIN_SNAPSHOTS)
            continue

        X = np.array([vector_from_dict(r.features, keys) for r in rows], dtype=float)
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
        # Run blocking sklearn fit in executor to not block event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, model.fit, X)

        population = build_baseline((r.features for r in rows), keys)
        model_b64 = dumps_model(model, keys, population, len(rows), trained_at)
        await redis.set(model_key, model_b64, ex=MODEL_TTL)
        await _store_entity_profiles(entity_type, rows, keys)
        trained_any = True
        log.info("ueba_model_trained", entity_type=entity_type, n_samples=len(rows))

    status = "ready" if trained_any else "cold"
    await redis.set("ueba:model:status", status)
    if trained_any:
        await redis.set("ueba:model:trained_at", datetime.now(timezone.utc).isoformat())
    log.info("ueba_train_complete", status=status)
