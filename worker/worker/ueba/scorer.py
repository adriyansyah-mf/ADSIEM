# worker/worker/ueba/scorer.py
import hashlib
import time
from datetime import datetime, timezone

import numpy as np
import structlog
from sqlalchemy.dialects.postgresql import insert as pg_insert

from worker.alert_manager import create_alert
from worker.database import AsyncSessionLocal
from worker.models import UebaAnomaly, UebaEntityScore
from worker.ueba.explain import assess, explain, mitre_for, next_risk
from worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS,
    update_user_counters, update_ip_counters,
    build_user_vector_dict, build_ip_vector_dict,
    vector_from_dict,
)
from worker.ueba.model_codec import ModelBundle, loads_model

log = structlog.get_logger()

# decision_function < 0 is the forest's own outlier boundary (set by contamination);
# ueba.explain.assess() then requires a deviating feature before it counts.
ANOMALY_THRESHOLD = 0.0
COOLDOWN_TTL = 1800          # 30 minutes between alerts for the same entity
MODEL_CACHE_TTL = 300        # reload model from Redis every 5 minutes
MIN_ANOMALY_COUNT = 3        # suppress alerts until entity has this many anomalies (cold entity guard)
STRONG_ANOMALY = 0.9         # …unless a single anomaly is this strong
ANOMALY_RECORD_WINDOW = 300  # record an entity's anomaly at most once per 5 min…
WORSE_BY = 0.1               # …unless its anomaly strength grew by this much

_FEATURE_KEYS = {"user": USER_FEATURE_KEYS, "ip": IP_FEATURE_KEYS}
_bundles: dict[str, ModelBundle | None] = {"user": None, "ip": None}
_model_loaded_at: float = 0
_reported: set[str] = set()  # blob digests already logged as unusable (log once, not per event)


def _decode(entity_type: str, blob: str) -> ModelBundle | None:
    digest = hashlib.sha1(blob.encode()).hexdigest()
    try:
        bundle = loads_model(blob)
    except Exception as exc:
        if digest not in _reported:
            _reported.add(digest)
            log.error("ueba_model_load_failed", entity_type=entity_type, error=str(exc))
        return None
    problem = None
    if bundle is None:
        problem = "outdated model format; waiting for the next training run"
    elif bundle.feature_keys != _FEATURE_KEYS[entity_type]:
        problem = "model was trained on a different feature set; waiting for retraining"
    if problem:
        if digest not in _reported:
            _reported.add(digest)
            log.warning("ueba_model_unusable", entity_type=entity_type, reason=problem)
        return None
    return bundle


async def _load_models(redis) -> bool:
    global _model_loaded_at
    if time.time() - _model_loaded_at < MODEL_CACHE_TTL:
        return any(_bundles.values())
    _model_loaded_at = time.time()  # also throttles polling while the model is cold

    if await redis.get("ueba:model:status") != "ready":
        return False
    for entity_type in _bundles:
        blob = await redis.get(f"ueba:model:{entity_type}")
        _bundles[entity_type] = _decode(entity_type, blob) if blob else None
    return any(_bundles.values())


async def _handle_score(
    redis, entity_type: str, entity_value: str, bundle: ModelBundle,
    feat: dict, group_id: str, decoded: dict,
) -> None:
    vec = np.array([vector_from_dict(feat, bundle.feature_keys)])
    score = float(bundle.model.decision_function(vec)[0])

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        row = await db.get(UebaEntityScore, (entity_type, entity_value))
        reasons = explain(entity_type, feat, row.feature_profile if row else None, bundle.baseline)
        strength = assess(score, ANOMALY_THRESHOLD, reasons)

        # The features are hourly windows, so every event of a burst looks the
        # same; count it as a new anomaly once per window unless it gets worse:
        # stronger, or a feature that wasn't deviating before now is.
        is_new_anomaly = False
        if strength > 0:
            rec_key = f"ueba:rec:{entity_type}:{entity_value}"
            features_now = sorted(r["feature"] for r in reasons)
            last = await redis.get(rec_key)
            if last is None:
                is_new_anomaly = True
            else:
                last_strength, _, last_features = last.partition("|")
                is_new_anomaly = (strength > float(last_strength) + WORSE_BY
                                  or not set(features_now) <= set(filter(None, last_features.split(","))))
            if is_new_anomaly:
                await redis.set(rec_key, f"{strength:.4f}|{','.join(features_now)}", ex=ANOMALY_RECORD_WINDOW)

        last_update = (row.updated_at or row.last_seen_at) if row else None
        since = (now - last_update).total_seconds() if last_update else 0.0
        new_risk = next_risk(row.risk_score if row else 0.0, since, strength if is_new_anomaly else 0.0)

        if is_new_anomaly:
            anomaly_count = (row.anomaly_count if row else 0) + 1
            mitre = mitre_for(entity_type, reasons)
            alert_id = None
            cd_key = f"ueba:cd:{entity_type}:{entity_value}"
            # the cold-entity guard is for marginal anomalies; a glaring one alerts at once
            if (anomaly_count >= MIN_ANOMALY_COUNT or strength >= STRONG_ANOMALY) and not await redis.exists(cd_key):
                alert_id = await _raise_alert(entity_type, entity_value, new_risk, score,
                                              reasons, mitre, feat, group_id, decoded)
                await redis.setex(cd_key, COOLDOWN_TTL, "1")
            db.add(UebaAnomaly(
                entity_type=entity_type, entity_value=entity_value, group_id=group_id,
                anomaly_score=score, risk_score=new_risk, features=feat, alert_id=alert_id,
                mitre_techniques=mitre, reasons=reasons,
            ))

        stmt = pg_insert(UebaEntityScore).values(
            entity_type=entity_type, entity_value=entity_value, group_id=group_id,
            risk_score=new_risk, anomaly_count=1 if is_new_anomaly else 0,
            last_anomaly_at=now if is_new_anomaly else None, last_seen_at=now, updated_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["entity_type", "entity_value"],
            set_={
                "risk_score":      stmt.excluded.risk_score,
                "last_seen_at":    stmt.excluded.last_seen_at,
                "updated_at":      now,
                "anomaly_count":   UebaEntityScore.anomaly_count + (1 if is_new_anomaly else 0),
                "last_anomaly_at": stmt.excluded.last_anomaly_at if is_new_anomaly
                                   else UebaEntityScore.last_anomaly_at,
            },
        )
        await db.execute(stmt)
        await db.commit()


async def _raise_alert(entity_type, entity_value, risk, score, reasons, mitre, feat, group_id, decoded):
    severity = (
        "critical" if risk >= 80 else
        "high"     if risk >= 60 else
        "medium"   if risk >= 40 else "low"
    )
    why = f" — {reasons[0]['text']}" if reasons else ""
    alert_id = await create_alert(
        rule_match={
            "id":         f"ueba-{entity_type}",
            "title":      f"[UEBA] {entity_type.capitalize()} anomaly: {entity_value}{why} [risk: {risk:.0f}/100]",
            "level":      severity,
            "tags":       ["ueba", f"ueba.{entity_type}"],
            "mitre_tags": [f"attack.{m['id'].lower()}" for m in mitre],
            # handed to the AI analyst as the event context
            "matched_fields": {"ueba_entity_type": entity_type, "ueba_entity_value": entity_value,
                               "ueba_reasons": [r["text"] for r in reasons], "ueba_features": feat,
                               "ueba_score": round(score, 4), "ueba_risk": risk},
        },
        event_id=None, agent_id=None, group_id=group_id,
        source_ip=entity_value if entity_type == "ip" else decoded.get("source.ip"),
        hostname=decoded.get("hostname") or decoded.get("host.hostname"),
    )
    log.info("ueba_alert_created", entity_type=entity_type, entity_value=entity_value,
             risk=risk, score=score, reasons=[r["feature"] for r in reasons])
    return alert_id


async def score_event(redis, decoded: dict, group_id: str) -> None:
    """Entry point called from consumer.py after each event is saved."""
    user = decoded.get("user.name")
    ip   = decoded.get("source.ip")

    # Always update counters (even when model is cold — builds training data)
    if user:
        await update_user_counters(redis, user, decoded)
    if ip:
        await update_ip_counters(redis, ip, decoded, user)

    if not await _load_models(redis):
        return  # model cold, not yet trained, or unusable (logged once)

    if user and _bundles["user"] is not None:
        login  = int(await redis.get(f"ueba:u:{user}:login")  or 0)
        failed = int(await redis.get(f"ueba:u:{user}:failed") or 0)
        feat = await build_user_vector_dict(redis, user, login, failed)
        await _handle_score(redis, "user", user, _bundles["user"], feat, group_id, decoded)

    if ip and _bundles["ip"] is not None:
        total  = int(await redis.get(f"ueba:ip:{ip}:total")  or 0)
        failed = int(await redis.get(f"ueba:ip:{ip}:failed") or 0)
        feat = await build_ip_vector_dict(redis, ip, total, failed)
        await _handle_score(redis, "ip", ip, _bundles["ip"], feat, group_id, decoded)
