# worker/worker/ueba/scorer.py
import base64
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

ANOMALY_THRESHOLD = -0.1
COOLDOWN_TTL = 1800   # 30 minutes between alerts for the same entity
MODEL_CACHE_TTL = 300  # reload model from Redis every 5 minutes
MIN_ANOMALY_COUNT = 3  # suppress alerts until entity has this many anomalies (cold entity guard)

_user_model = None
_ip_model = None
_model_loaded_at: float = 0


async def _load_models(redis) -> bool:
    global _user_model, _ip_model, _model_loaded_at
    if time.time() - _model_loaded_at < MODEL_CACHE_TTL:
        return _user_model is not None or _ip_model is not None

    status = await redis.get("ueba:model:status")
    if status != "ready":
        _model_loaded_at = time.time()  # avoid polling every event when cold
        return False

    user_b64 = await redis.get("ueba:model:user")
    ip_b64   = await redis.get("ueba:model:ip")

    if user_b64:
        _user_model = pickle.loads(base64.b64decode(user_b64))
    if ip_b64:
        _ip_model = pickle.loads(base64.b64decode(ip_b64))

    _model_loaded_at = time.time()
    return _user_model is not None or _ip_model is not None


async def _get_risk_score(entity_type: str, entity_value: str) -> float:
    async with AsyncSessionLocal() as db:
        row = await db.get(UebaEntityScore, (entity_type, entity_value))
        return row.risk_score if row else 0.0


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


async def _get_anomaly_count(entity_type: str, entity_value: str) -> int:
    async with AsyncSessionLocal() as db:
        row = await db.get(UebaEntityScore, (entity_type, entity_value))
        return row.anomaly_count if row else 0


async def _handle_score(
    redis, entity_type: str, entity_value: str,
    if_score: float, feat_dict: dict,
    group_id: str, decoded: dict,
) -> None:
    old_risk = await _get_risk_score(entity_type, entity_value)
    contribution = min(abs(if_score) * 100, 100)
    new_risk = old_risk * 0.9 + contribution * 0.1

    is_anomaly = if_score < ANOMALY_THRESHOLD

    if is_anomaly:
        cd_key = f"ueba:cd:{entity_type}:{entity_value}"
        in_cooldown = await redis.exists(cd_key)
        anomaly_count = await _get_anomaly_count(entity_type, entity_value)

        if not in_cooldown and (anomaly_count + 1) >= MIN_ANOMALY_COUNT:
            severity = (
                "critical" if new_risk >= 80 else
                "high"     if new_risk >= 60 else
                "medium"   if new_risk >= 40 else "low"
            )
            title = (
                f"[UEBA] {entity_type.capitalize()} anomaly: {entity_value} "
                f"[risk: {new_risk:.0f}/100]"
            )
            src_ip = entity_value if entity_type == "ip" else decoded.get("source.ip")
            hostname = decoded.get("hostname") or decoded.get("host.hostname")

            alert_id = await create_alert(
                rule_match={
                    "id":         f"ueba-{entity_type}",
                    "title":      title,
                    "level":      severity,
                    "tags":       ["ueba", f"ueba.{entity_type}"],
                    "mitre_tags": [],
                },
                event_id=None, agent_id=None,
                group_id=group_id, source_ip=src_ip, hostname=hostname,
            )
            await redis.setex(cd_key, COOLDOWN_TTL, "1")
            log.info("ueba_alert_created", entity_type=entity_type, entity_value=entity_value,
                     risk=new_risk, score=if_score)
        else:
            alert_id = None

        # Always record the anomaly in the DB (for timeline)
        async with AsyncSessionLocal() as db:
            db.add(UebaAnomaly(
                entity_type=entity_type, entity_value=entity_value, group_id=group_id,
                anomaly_score=if_score, risk_score=new_risk,
                features=feat_dict, alert_id=alert_id,
            ))
            await db.commit()

    await _upsert_entity_score(entity_type, entity_value, group_id, new_risk, is_anomaly)


async def score_event(redis, decoded: dict, group_id: str) -> None:
    """Entry point called from consumer.py after each event is saved."""
    user = decoded.get("user.name")
    ip   = decoded.get("source.ip")

    # Always update counters (even when model is cold — builds training data)
    if user:
        await update_user_counters(redis, user, decoded)
    if ip:
        await update_ip_counters(redis, ip, decoded, user)
    hostname = decoded.get("hostname") or decoded.get("host.hostname")
    if hostname:
        await update_host_counters(redis, hostname, decoded, user)

    if not await _load_models(redis):
        return  # model cold or not yet trained

    if user and _user_model is not None:
        login  = int(await redis.get(f"ueba:u:{user}:login")  or 0)
        failed = int(await redis.get(f"ueba:u:{user}:failed") or 0)
        feat = await build_user_vector_dict(redis, user, login, failed)
        vec  = np.array([vector_from_dict(feat, USER_FEATURE_KEYS)])
        score = float(_user_model.decision_function(vec)[0])
        await _handle_score(redis, "user", user, score, feat, group_id, decoded)

    if ip and _ip_model is not None:
        total  = int(await redis.get(f"ueba:ip:{ip}:total")  or 0)
        failed = int(await redis.get(f"ueba:ip:{ip}:failed") or 0)
        feat = await build_ip_vector_dict(redis, ip, total, failed)
        vec  = np.array([vector_from_dict(feat, IP_FEATURE_KEYS)])
        score = float(_ip_model.decision_function(vec)[0])
        await _handle_score(redis, "ip", ip, score, feat, group_id, decoded)
