# worker/worker/ueba/trainer.py
import asyncio
import base64
import json
import pickle
import statistics
import structlog
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, delete
from sqlalchemy.dialects.postgresql import insert as pg_insert

from worker.database import AsyncSessionLocal
from worker.models import UebaFeatureSnapshot, UebaEntityScore
from worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS, HOST_FEATURE_KEYS,
    build_user_vector_dict, build_ip_vector_dict, build_host_vector_dict,
    vector_from_dict,
)

log = structlog.get_logger()

MIN_SNAPSHOTS = 50   # global model threshold (unchanged)
MIN_PROFILE   = 24   # per-entity Z-score profile threshold
MODEL_TTL     = 7200 # 2 hours


def _compute_profile(snapshots: list[dict], keys: list[str]) -> dict:
    """Build mean/std profile for Z-score scoring. Requires >= 1 snapshot."""
    profile = {}
    for key in keys:
        values = [float(s.get(key, 0.0)) for s in snapshots]
        mean = statistics.mean(values) if values else 0.0
        std  = (statistics.stdev(values) if len(values) >= 2 else 0.0) or 0.1
        profile[key] = {"mean": mean, "std": std}
    return profile


def _get_prev_count(past_features: list[dict], count_key: str) -> float:
    """Return the previous snapshot's count for velocity calculation."""
    if not past_features:
        return 0.0
    return float(past_features[-1].get(count_key, 0.0))


def _get_mean_hour(past_features: list[dict]) -> float:
    """Return mean hour_of_day from historical snapshots."""
    hours = [s.get("hour_of_day", 12.0) for s in past_features]
    return statistics.mean(hours) if hours else 12.0


async def _get_past_snapshots(db, entity_type: str, entity_value: str, cutoff) -> list:
    result = await db.execute(
        select(UebaFeatureSnapshot)
        .where(UebaFeatureSnapshot.entity_type == entity_type)
        .where(UebaFeatureSnapshot.entity_value == entity_value)
        .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
        .order_by(UebaFeatureSnapshot.snapshot_hour.asc())
    )
    return result.scalars().all()


async def _get_current_risk(db, entity_type: str, entity_value: str) -> float:
    row = await db.get(UebaEntityScore, (entity_type, entity_value))
    return row.risk_score if row else 0.0


async def _upsert_profile(db, entity_type: str, entity_value: str, profile: dict) -> None:
    existing = await db.get(UebaEntityScore, (entity_type, entity_value))
    if existing:
        existing.feature_profile = profile
    # If not existing yet, profile will be set on next risk score upsert


async def take_snapshots(redis) -> None:
    now = datetime.now(timezone.utc)
    snapshot_hour = now.replace(minute=0, second=0, microsecond=0)
    cutoff = now - timedelta(days=7)

    users = await redis.smembers("ueba:active:users")
    ips   = await redis.smembers("ueba:active:ips")
    hosts = await redis.smembers("ueba:active:hosts")

    async with AsyncSessionLocal() as db:
        # ── Users ─────────────────────────────────────────────────
        for user in users:
            login  = int(await redis.get(f"ueba:u:{user}:login")  or 0)
            failed = int(await redis.get(f"ueba:u:{user}:failed") or 0)

            past = await _get_past_snapshots(db, "user", user, cutoff)
            past_feats = [p.features for p in past]
            prev_count = _get_prev_count(past_feats, "login_count")
            mean_hour  = _get_mean_hour(past_feats)

            feat = await build_user_vector_dict(
                redis, user, login, failed,
                prev_login_count=int(prev_count), mean_hour=mean_hour,
            )

            profile = _compute_profile(past_feats + [feat], USER_FEATURE_KEYS) if len(past_feats) >= MIN_PROFILE - 1 else {}
            current_risk = await _get_current_risk(db, "user", user)

            stmt = pg_insert(UebaFeatureSnapshot).values(
                entity_type="user", entity_value=user, group_id="default",
                features=feat, snapshot_hour=snapshot_hour, risk_score=current_risk,
            ).on_conflict_do_update(
                index_elements=["entity_type", "entity_value", "group_id", "snapshot_hour"],
                set_={"features": feat, "risk_score": current_risk},
            )
            await db.execute(stmt)

            if profile:
                await _upsert_profile(db, "user", user, profile)

        # ── IPs ───────────────────────────────────────────────────
        for ip in ips:
            total  = int(await redis.get(f"ueba:ip:{ip}:total")  or 0)
            failed = int(await redis.get(f"ueba:ip:{ip}:failed") or 0)

            past = await _get_past_snapshots(db, "ip", ip, cutoff)
            past_feats = [p.features for p in past]
            prev_count = _get_prev_count(past_feats, "total_events")

            feat = await build_ip_vector_dict(redis, ip, total, failed, prev_total=int(prev_count))

            profile = _compute_profile(past_feats + [feat], IP_FEATURE_KEYS) if len(past_feats) >= MIN_PROFILE - 1 else {}
            current_risk = await _get_current_risk(db, "ip", ip)

            stmt = pg_insert(UebaFeatureSnapshot).values(
                entity_type="ip", entity_value=ip, group_id="default",
                features=feat, snapshot_hour=snapshot_hour, risk_score=current_risk,
            ).on_conflict_do_update(
                index_elements=["entity_type", "entity_value", "group_id", "snapshot_hour"],
                set_={"features": feat, "risk_score": current_risk},
            )
            await db.execute(stmt)

            if profile:
                await _upsert_profile(db, "ip", ip, profile)

        # ── Hosts ─────────────────────────────────────────────────
        for host in hosts:
            total  = int(await redis.get(f"ueba:host:{host}:total")  or 0)
            failed = int(await redis.get(f"ueba:host:{host}:failed") or 0)

            past = await _get_past_snapshots(db, "host", host, cutoff)
            past_feats = [p.features for p in past]
            prev_count = _get_prev_count(past_feats, "total_events")

            feat = await build_host_vector_dict(redis, host, total, failed, prev_total=int(prev_count))

            profile = _compute_profile(past_feats + [feat], HOST_FEATURE_KEYS) if len(past_feats) >= MIN_PROFILE - 1 else {}
            current_risk = await _get_current_risk(db, "host", host)

            stmt = pg_insert(UebaFeatureSnapshot).values(
                entity_type="host", entity_value=host, group_id="default",
                features=feat, snapshot_hour=snapshot_hour, risk_score=current_risk,
            ).on_conflict_do_update(
                index_elements=["entity_type", "entity_value", "group_id", "snapshot_hour"],
                set_={"features": feat, "risk_score": current_risk},
            )
            await db.execute(stmt)

            if profile:
                await _upsert_profile(db, "host", host, profile)

        # Prune > 8 days
        prune_cutoff = now - timedelta(days=8)
        await db.execute(
            delete(UebaFeatureSnapshot).where(UebaFeatureSnapshot.snapshot_hour < prune_cutoff)
        )
        await db.commit()

    log.info("ueba_snapshots_saved", users=len(users), ips=len(ips), hosts=len(hosts))


async def train_models(redis) -> None:
    """Load DB snapshots, train IF+LOF ensemble per entity type, pickle to Redis."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    trained_any = False

    entity_configs = [
        ("user", USER_FEATURE_KEYS, "ueba:model:user:if", "ueba:model:user:lof"),
        ("ip",   IP_FEATURE_KEYS,   "ueba:model:ip:if",   "ueba:model:ip:lof"),
        ("host", HOST_FEATURE_KEYS, "ueba:model:host:if", "ueba:model:host:lof"),
    ]

    async with AsyncSessionLocal() as db:
        for entity_type, keys, if_key, lof_key in entity_configs:
            rows = (await db.execute(
                select(UebaFeatureSnapshot)
                .where(UebaFeatureSnapshot.entity_type == entity_type)
                .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
            )).scalars().all()

            if len(rows) < MIN_SNAPSHOTS:
                log.info("ueba_cold_start", entity_type=entity_type, n=len(rows), needed=MIN_SNAPSHOTS)
                continue

            X = np.array([vector_from_dict(r.features, keys) for r in rows], dtype=float)
            loop = asyncio.get_running_loop()

            if_model  = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
            lof_model = LocalOutlierFactor(n_neighbors=20, contamination=0.05, novelty=True)

            await loop.run_in_executor(None, if_model.fit, X)
            await loop.run_in_executor(None, lof_model.fit, X)

            await redis.set(if_key,  base64.b64encode(pickle.dumps(if_model)).decode(),  ex=MODEL_TTL)
            await redis.set(lof_key, base64.b64encode(pickle.dumps(lof_model)).decode(), ex=MODEL_TTL)

            trained_any = True
            log.info("ueba_model_trained", entity_type=entity_type, n_samples=len(rows))

    status = "ready" if trained_any else "cold"
    await redis.set("ueba:model:status", status)
    if trained_any:
        await redis.set("ueba:model:trained_at", datetime.now(timezone.utc).isoformat())
    log.info("ueba_train_complete", status=status)
