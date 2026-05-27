# worker/worker/ueba/scorer.py
import base64
import json
import pickle
import time
import numpy as np
import structlog
from datetime import datetime, timezone
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.models import UebaEntityScore, UebaAnomaly
from worker.alert_manager import create_alert
from worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS, HOST_FEATURE_KEYS,
    update_user_counters, update_ip_counters, update_host_counters,
    build_user_vector_dict, build_ip_vector_dict, build_host_vector_dict,
    vector_from_dict,
)

log = structlog.get_logger()

ANOMALY_THRESHOLD    = -0.1   # ensemble score threshold for recording anomaly
INVESTIGATE_THRESHOLD = -0.2  # stricter threshold to push to AI investigation queue
INVESTIGATE_RISK_MIN  = 50    # minimum risk score to trigger investigation
INV_COOLDOWN_TTL      = 3600  # 1 hour between investigations of same entity
COOLDOWN_TTL          = 1800  # 30 min between alerts for same entity
MODEL_CACHE_TTL       = 300   # reload models from Redis every 5 min
MIN_ANOMALY_COUNT     = 3     # cold entity guard

UEBA_INVESTIGATE_QUEUE = "siem:ueba:investigate"

_models: dict = {}  # {key: model}
_model_loaded_at: float = 0


async def _load_models(redis) -> bool:
    global _models, _model_loaded_at
    if time.time() - _model_loaded_at < MODEL_CACHE_TTL:
        return bool(_models)

    status = await redis.get("ueba:model:status")
    if status != "ready":
        _model_loaded_at = time.time()
        return False

    new_models = {}
    for key in [
        "ueba:model:user:if", "ueba:model:user:lof",
        "ueba:model:ip:if",   "ueba:model:ip:lof",
        "ueba:model:host:if", "ueba:model:host:lof",
    ]:
        b64 = await redis.get(key)
        if b64:
            new_models[key] = pickle.loads(base64.b64decode(b64))

    _models = new_models
    _model_loaded_at = time.time()
    return bool(_models)


def _ensemble_score(entity_type: str, vec: np.ndarray) -> float | None:
    """Return combined IF+LOF decision score, or None if models not available."""
    if_key  = f"ueba:model:{entity_type}:if"
    lof_key = f"ueba:model:{entity_type}:lof"
    if if_key not in _models and lof_key not in _models:
        return None
    scores = []
    if if_key in _models:
        scores.append(float(_models[if_key].decision_function(vec)[0]))
    if lof_key in _models:
        scores.append(float(_models[lof_key].decision_function(vec)[0]))
    return sum(scores) / len(scores)


def _zscore_contribution(feat_dict: dict, profile: dict, keys: list[str]) -> float | None:
    """Compute normalized Z-score contribution (0-100) from entity profile."""
    if not profile:
        return None
    z_scores = []
    for key in keys:
        p = profile.get(key)
        if not p:
            continue
        std = p["std"] or 0.1
        z = abs(feat_dict.get(key, 0.0) - p["mean"]) / std
        z_scores.append(z)
    if not z_scores:
        return None
    return min(max(z_scores) * 20, 100.0)  # scale max z-score to 0-100


async def _get_entity_score_row(entity_type: str, entity_value: str):
    async with AsyncSessionLocal() as db:
        return await db.get(UebaEntityScore, (entity_type, entity_value))


async def _upsert_entity_score(
    entity_type: str, entity_value: str, group_id: str,
    new_risk: float, is_anomaly: bool,
) -> None:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        existing = await db.get(UebaEntityScore, (entity_type, entity_value))
        if existing:
            existing.risk_score   = new_risk
            existing.last_seen_at = now
            existing.updated_at   = now
            if is_anomaly:
                existing.anomaly_count   += 1
                existing.last_anomaly_at  = now
        else:
            db.add(UebaEntityScore(
                entity_type=entity_type, entity_value=entity_value,
                group_id=group_id, risk_score=new_risk,
                anomaly_count=1 if is_anomaly else 0,
                last_anomaly_at=now if is_anomaly else None,
                last_seen_at=now,
            ))
        await db.commit()


async def _handle_score(
    redis, entity_type: str, entity_value: str,
    ensemble_score: float | None,
    feat_dict: dict, feat_keys: list[str],
    group_id: str, decoded: dict,
) -> None:
    row = await _get_entity_score_row(entity_type, entity_value)
    old_risk = row.risk_score if row else 0.0
    profile  = row.feature_profile if row else {}
    anomaly_count = row.anomaly_count if row else 0

    # Compute risk contributions
    zscore_contrib = _zscore_contribution(feat_dict, profile, feat_keys)
    global_contrib = min(abs(ensemble_score) * 100, 100.0) if ensemble_score is not None else None

    # Combined risk raw value
    if zscore_contrib is not None and global_contrib is not None:
        raw = zscore_contrib * 0.6 + global_contrib * 0.4
    elif zscore_contrib is not None:
        raw = zscore_contrib
    elif global_contrib is not None:
        raw = global_contrib
    else:
        return  # no scoring data available

    new_risk = old_risk * 0.9 + raw * 0.1

    is_anomaly = ensemble_score is not None and ensemble_score < ANOMALY_THRESHOLD
    alert_id = None

    if is_anomaly:
        cd_key = f"ueba:cd:{entity_type}:{entity_value}"
        in_cooldown = await redis.exists(cd_key)

        if not in_cooldown and (anomaly_count + 1) >= MIN_ANOMALY_COUNT:
            severity = (
                "critical" if new_risk >= 80 else
                "high"     if new_risk >= 60 else
                "medium"   if new_risk >= 40 else "low"
            )
            src_ip   = entity_value if entity_type == "ip" else decoded.get("source.ip")
            hostname = (entity_value if entity_type == "host"
                        else decoded.get("hostname") or decoded.get("host.hostname"))

            alert_id = await create_alert(
                rule_match={
                    "id":         f"ueba-{entity_type}",
                    "title":      f"[UEBA] {entity_type.capitalize()} anomaly: {entity_value} [risk: {new_risk:.0f}/100]",
                    "level":      severity,
                    "tags":       ["ueba", f"ueba.{entity_type}"],
                    "mitre_tags": [],
                },
                event_id=None, agent_id=None,
                group_id=group_id, source_ip=src_ip, hostname=hostname,
            )
            await redis.setex(cd_key, COOLDOWN_TTL, "1")
            log.info("ueba_alert_created", entity_type=entity_type, entity_value=entity_value,
                     risk=new_risk, score=ensemble_score)

        # Record anomaly in DB
        async with AsyncSessionLocal() as db:
            anomaly = UebaAnomaly(
                entity_type=entity_type, entity_value=entity_value, group_id=group_id,
                anomaly_score=ensemble_score, risk_score=new_risk,
                features=feat_dict, alert_id=alert_id,
            )
            db.add(anomaly)
            await db.flush()
            anomaly_id = str(anomaly.id)
            await db.commit()

        # Push to investigation queue if score extreme enough
        if (ensemble_score < INVESTIGATE_THRESHOLD and new_risk >= INVESTIGATE_RISK_MIN):
            inv_cd_key = f"ueba:inv_cd:{entity_type}:{entity_value}"
            if not await redis.exists(inv_cd_key):
                await redis.setex(inv_cd_key, INV_COOLDOWN_TTL, "1")
                src_ip_inv   = entity_value if entity_type == "ip" else decoded.get("source.ip")
                hostname_inv = (entity_value if entity_type == "host"
                                else decoded.get("hostname") or decoded.get("host.hostname"))
                await redis.rpush(UEBA_INVESTIGATE_QUEUE, json.dumps({
                    "entity_type":   entity_type,
                    "entity_value":  entity_value,
                    "group_id":      group_id,
                    "anomaly_score": ensemble_score,
                    "risk_score":    new_risk,
                    "features":      feat_dict,
                    "anomaly_id":    anomaly_id,
                    "source_ip":     src_ip_inv,
                    "hostname":      hostname_inv,
                }))
                log.info("ueba_queued_for_investigation",
                         entity_type=entity_type, entity_value=entity_value,
                         score=ensemble_score, risk=new_risk)

    await _upsert_entity_score(entity_type, entity_value, group_id, new_risk, is_anomaly)


async def score_event(redis, decoded: dict, group_id: str) -> None:
    """Entry point called from consumer.py after each event is saved."""
    user     = decoded.get("user.name")
    ip       = decoded.get("source.ip")
    hostname = decoded.get("hostname") or decoded.get("host.hostname")

    # Always update counters (builds training data even when model cold)
    if user:
        await update_user_counters(redis, user, decoded)
    if ip:
        await update_ip_counters(redis, ip, decoded, user)
    if hostname:
        await update_host_counters(redis, hostname, decoded, user)

    if not await _load_models(redis):
        return

    if user:
        login  = int(await redis.get(f"ueba:u:{user}:login")  or 0)
        failed = int(await redis.get(f"ueba:u:{user}:failed") or 0)
        feat = await build_user_vector_dict(redis, user, login, failed)
        vec  = np.array([vector_from_dict(feat, USER_FEATURE_KEYS)])
        score = _ensemble_score("user", vec)
        await _handle_score(redis, "user", user, score, feat, USER_FEATURE_KEYS, group_id, decoded)

    if ip:
        total  = int(await redis.get(f"ueba:ip:{ip}:total")  or 0)
        failed = int(await redis.get(f"ueba:ip:{ip}:failed") or 0)
        feat = await build_ip_vector_dict(redis, ip, total, failed)
        vec  = np.array([vector_from_dict(feat, IP_FEATURE_KEYS)])
        score = _ensemble_score("ip", vec)
        await _handle_score(redis, "ip", ip, score, feat, IP_FEATURE_KEYS, group_id, decoded)

    if hostname:
        total  = int(await redis.get(f"ueba:host:{hostname}:total")  or 0)
        failed = int(await redis.get(f"ueba:host:{hostname}:failed") or 0)
        feat = await build_host_vector_dict(redis, hostname, total, failed)
        vec  = np.array([vector_from_dict(feat, HOST_FEATURE_KEYS)])
        score = _ensemble_score("host", vec)
        await _handle_score(redis, "host", hostname, score, feat, HOST_FEATURE_KEYS, group_id, decoded)
