# worker/worker/ueba/trainer.py
import asyncio
import json
import structlog
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, delete, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from worker.database import AsyncSessionLocal
from worker.models import UebaEntityScore, UebaFeatureSnapshot
from worker.ueba.explain import MIN_ENTITY_SNAPSHOTS, build_baseline
from worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS, HOST_FEATURE_KEYS, PROCESS_FEATURE_KEYS,
    build_user_vector_dict, build_ip_vector_dict, build_host_vector_dict, build_process_vector_dict,
    vector_from_dict,
)
from worker.ueba.model_codec import dumps_model

log = structlog.get_logger()

MIN_SNAPSHOTS = 50
MODEL_TTL = 7200  # 2 hours — trainer rewrites every hour


async def _vector(redis, entity_type: str, value: str) -> dict:
    if entity_type == "user":
        login = int(await redis.get(f"ueba:u:{value}:login") or 0)
        failed = int(await redis.get(f"ueba:u:{value}:failed") or 0)
        return await build_user_vector_dict(redis, value, login, failed)
    if entity_type == "ip":
        total = int(await redis.get(f"ueba:ip:{value}:total") or 0)
        failed = int(await redis.get(f"ueba:ip:{value}:failed") or 0)
        return await build_ip_vector_dict(redis, value, total, failed)
    if entity_type == "host":
        return await build_host_vector_dict(redis, value)
    return await build_process_vector_dict(redis, value)


async def take_snapshots(redis) -> None:
    """Read active entities from Redis, build feature dicts, upsert hourly snapshot to DB,
    each under the group the entity was last seen in (ueba:group:<type>)."""
    now = datetime.now(timezone.utc)
    snapshot_hour = now.replace(minute=0, second=0, microsecond=0)
    counts = {}

    async with AsyncSessionLocal() as db:
        for entity_type, active in ACTIVE_SETS.items():
            values = await redis.smembers(active)
            groups = await redis.hgetall(f"ueba:group:{entity_type}") or {}
            counts[entity_type] = len(values)
            for value in values:
                feat = await _vector(redis, entity_type, value)
                stmt = pg_insert(UebaFeatureSnapshot).values(
                    entity_type=entity_type, entity_value=value, group_id=groups.get(value) or "default",
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

    log.info("ueba_snapshots_saved", **counts)


ACTIVE_SETS = {"user": "ueba:active:users", "ip": "ueba:active:ips",
               "host": "ueba:active:hosts", "process": "ueba:active:processes"}
FEATURE_KEYS = {"user": USER_FEATURE_KEYS, "ip": IP_FEATURE_KEYS,
                "host": HOST_FEATURE_KEYS, "process": PROCESS_FEATURE_KEYS}
_ACTIVITY_KEYS = {"user": ("login_count",), "ip": ("total_events",),
                  "host": ("process_count", "outbound_conns"), "process": ("exec_count", "outbound_conns")}
GROUP_BASELINE_KEY = "ueba:baseline:{}:{}"


def active_snapshots(entity_type: str, rows):
    """Drop hourly snapshots of entities that did nothing that hour. Their
    counters had already expired, and keeping them drags every baseline to
    zero — after which any active IP looks wildly abnormal."""
    keys = _ACTIVITY_KEYS[entity_type]
    return [r for r in rows if any(float((r.features or {}).get(k, 0) or 0) > 0 for k in keys)]


async def _store_group_baselines(redis, entity_type: str, rows, keys: list[str]) -> int:
    """Population baselines per group (a finance laptop is not compared with a
    build server); groups with fewer than MIN_SNAPSHOTS hours use the global one."""
    by_group: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_group[r.group_id or "default"].append(r.features)
    stored = 0
    for group, feats in by_group.items():
        if len(feats) < MIN_SNAPSHOTS:
            continue
        await redis.set(GROUP_BASELINE_KEY.format(entity_type, group),
                        json.dumps(build_baseline(feats, keys)), ex=MODEL_TTL)
        stored += 1
    return stored


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
        rows_by_type = {
            entity_type: (await db.execute(
                select(UebaFeatureSnapshot)
                .where(UebaFeatureSnapshot.entity_type == entity_type)
                .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
            )).scalars().all()
            for entity_type in FEATURE_KEYS
        }

    trained_any = False
    trained_at = datetime.now(timezone.utc).isoformat()

    for entity_type, keys in FEATURE_KEYS.items():
        model_key = f"ueba:model:{entity_type}"
        rows = active_snapshots(entity_type, rows_by_type[entity_type])
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
        groups = await _store_group_baselines(redis, entity_type, rows, keys)
        await _store_entity_profiles(entity_type, rows, keys)
        trained_any = True
        log.info("ueba_model_trained", entity_type=entity_type, n_samples=len(rows), group_baselines=groups)

    status = "ready" if trained_any else "cold"
    await redis.set("ueba:model:status", status)
    if trained_any:
        await redis.set("ueba:model:trained_at", datetime.now(timezone.utc).isoformat())
    log.info("ueba_train_complete", status=status)
