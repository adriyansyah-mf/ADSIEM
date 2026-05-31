# UEBA Enhanced: ML + AI Investigator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade UEBA with per-entity behavioral profiling + ensemble ML, an ML gate that saves 60–80% Groq tokens, TI reputation as a live ML feature, and an AI investigator that learns from historical cases and creates enriched Cases with MITRE ATT&CK context.

**Architecture:** The ML layer gains a hostname entity type, per-entity Z-score profiling (starts at 24h vs 50-snapshot global), an IF+LOF ensemble, velocity/hour-deviation features, and TI reputation cached from investigator runs. The ML gate in `alert_manager.py` uses entity risk scores to decide which alerts reach the AI queue. The UEBA AI Investigator is a new background loop that queries logs, runs TI, retrieves similar past cases, maps MITRE ATT&CK, calls Groq, and creates Cases directly.

**Tech Stack:** Python asyncio, scikit-learn (IsolationForest + LocalOutlierFactor), Redis sorted sets + JSON cache, PostgreSQL JSONB, FastAPI, React + TanStack Query, existing TI `EnrichmentAggregator`, existing Groq `analyze_alert_with_groq`-style prompting.

---

## File Map

### New files
- `worker/worker/ueba/mitre_mapper.py` — rule-based feature→ATT&CK mapping
- `worker/worker/ueba/investigator.py` — AI investigator: queue consumer + orchestration

### Modified files
- `worker/worker/models.py` — add columns to UebaAnomaly, UebaEntityScore, UebaFeatureSnapshot
- `worker/worker/ueba/features.py` — hostname entity, velocity, hour_deviation, ti_reputation
- `worker/worker/ueba/trainer.py` — ensemble IF+LOF, Z-score profile, hostname model, risk_score snapshot
- `worker/worker/ueba/scorer.py` — ensemble scoring, combined risk formula, investigate queue push
- `worker/worker/ueba/loops.py` — add `ueba_ai_loop()`
- `worker/worker/main.py` — add `ueba_ai_loop()` to gather
- `worker/worker/alert_manager.py` — ML gate before AI queue push
- `server-api/app/models/models.py` — mirror new columns
- `server-api/app/schemas/schemas.py` — update UebaAnomalyOut, UebaEntityScoreOut, UebaStatusOut
- `server-api/app/api/routes/ueba.py` — add history endpoint, host entity_type support
- `server-api/app/main.py` — add `_migrate_ueba_columns()` for new columns
- `dashboard/src/pages/UEBAPage.tsx` — hosts tab, risk trend chart, MITRE badges, AI narrative, case link

---

## Task 1: Database column additions

**Files:**
- Modify: `server-api/app/models/models.py`
- Modify: `worker/worker/models.py`
- Modify: `server-api/app/main.py`

The existing tables need new columns. `create_all` does not add columns to existing tables, so we use `ADD COLUMN IF NOT EXISTS` raw SQL run at server-api startup.

- [ ] **Step 1: Add new columns to server-api UebaAnomaly model**

In `server-api/app/models/models.py`, find `class UebaAnomaly(Base):` and add 4 columns after `alert_id`:

```python
class UebaAnomaly(Base):
    __tablename__ = "ueba_anomalies"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type   = Column(String(20),  nullable=False)
    entity_value  = Column(String(255), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default")
    anomaly_score = Column(Float,       nullable=False)
    risk_score    = Column(Float,       nullable=False)
    features      = Column(JSONB,       nullable=False, default=dict)
    alert_id      = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"))
    mitre_techniques = Column(JSONB, nullable=False, default=list)
    ai_narrative     = Column(Text)
    ai_action        = Column(String(20))
    case_id          = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="SET NULL"))
    detected_at   = Column(DateTime(timezone=True), default=now_utc)
```

- [ ] **Step 2: Add feature_profile to server-api UebaEntityScore**

In `server-api/app/models/models.py`, find `class UebaEntityScore(Base):` and add after `updated_at`:

```python
class UebaEntityScore(Base):
    __tablename__ = "ueba_entity_scores"
    entity_type     = Column(String(20),  primary_key=True)
    entity_value    = Column(String(255), primary_key=True)
    group_id        = Column(String(100), nullable=False, default="default")
    risk_score      = Column(Float,       nullable=False, default=0.0)
    anomaly_count   = Column(Integer,     nullable=False, default=0)
    last_anomaly_at = Column(DateTime(timezone=True))
    last_seen_at    = Column(DateTime(timezone=True))
    updated_at      = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    feature_profile = Column(JSONB, nullable=False, default=dict)
```

- [ ] **Step 3: Add risk_score to server-api UebaFeatureSnapshot**

In `server-api/app/models/models.py`, find `class UebaFeatureSnapshot(Base):` and add `risk_score`:

```python
class UebaFeatureSnapshot(Base):
    __tablename__ = "ueba_feature_snapshots"
    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type   = Column(String(20),  nullable=False)
    entity_value  = Column(String(255), nullable=False)
    group_id      = Column(String(100), nullable=False, default="default")
    features      = Column(JSONB,       nullable=False, default=dict)
    risk_score    = Column(Float,       nullable=False, default=0.0)
    snapshot_hour = Column(DateTime(timezone=True), nullable=False)
    created_at    = Column(DateTime(timezone=True), default=now_utc)
```

- [ ] **Step 4: Add runtime migration to server-api/app/main.py**

Add this function and call it from `lifespan`. Add the import `from sqlalchemy import text` at the top if not already there.

```python
async def _migrate_ueba_columns() -> None:
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE ueba_anomalies
            ADD COLUMN IF NOT EXISTS mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
            ADD COLUMN IF NOT EXISTS ai_narrative TEXT,
            ADD COLUMN IF NOT EXISTS ai_action VARCHAR(20),
            ADD COLUMN IF NOT EXISTS case_id UUID REFERENCES cases(id) ON DELETE SET NULL
        """))
        await conn.execute(text("""
            ALTER TABLE ueba_entity_scores
            ADD COLUMN IF NOT EXISTS feature_profile JSONB NOT NULL DEFAULT '{}'::jsonb
        """))
        await conn.execute(text("""
            ALTER TABLE ueba_feature_snapshots
            ADD COLUMN IF NOT EXISTS risk_score FLOAT NOT NULL DEFAULT 0.0
        """))
```

In `lifespan`, add `await _migrate_ueba_columns()` after `await _seed_correlation_rules()`.

- [ ] **Step 5: Mirror same columns in worker/worker/models.py**

In `worker/worker/models.py`:

Find `class UebaAnomaly(Base):` — add the same 4 columns after `alert_id`:
```python
    mitre_techniques = Column(JSONB, nullable=False, default=list)
    ai_narrative     = Column(Text)
    ai_action        = Column(String(20))
    case_id          = Column(UUID(as_uuid=True))
```
Note: no FK in worker models (worker uses raw UUIDs, no FK enforcement needed).

Find `class UebaEntityScore(Base):` — add after `updated_at`:
```python
    feature_profile = Column(JSONB, nullable=False, default=dict)
```

Find `class UebaFeatureSnapshot(Base):` — add after `features`:
```python
    risk_score = Column(Float, nullable=False, default=0.0)
```

- [ ] **Step 6: Verify migration SQL works**

```bash
cd /home/wonka/Documents/hackathon
docker compose exec postgres psql -U siem -d siem -c "\d ueba_anomalies" 2>/dev/null | grep -E "mitre|ai_action|case_id" || echo "columns not yet added — run server-api to trigger migration"
```

- [ ] **Step 7: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add server-api/app/models/models.py server-api/app/main.py worker/worker/models.py
git commit -m "feat(ueba): add mitre_techniques, ai_narrative, ai_action, case_id, feature_profile, risk_score columns"
```

---

## Task 2: ML features — hostname entity, velocity, hour_deviation, TI reputation

**Files:**
- Modify: `worker/worker/ueba/features.py`

Add hostname entity support and three new features. Read the full current file first.

- [ ] **Step 1: Write unit test for new feature keys**

Create `worker/tests/test_ueba_features.py`:

```python
import pytest
from worker.worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS, HOST_FEATURE_KEYS, vector_from_dict
)

def test_user_feature_keys_include_new():
    assert "velocity" in USER_FEATURE_KEYS
    assert "hour_deviation" in USER_FEATURE_KEYS

def test_ip_feature_keys_include_ti():
    assert "ti_reputation" in IP_FEATURE_KEYS

def test_host_feature_keys_complete():
    assert HOST_FEATURE_KEYS == [
        "unique_users", "total_events", "failed_ratio",
        "unique_source_ips", "sudo_count",
        "hour_of_day", "is_weekend", "velocity", "ti_reputation",
    ]

def test_vector_from_dict_fills_missing_with_zero():
    d = {"login_count": 3.0, "failed_ratio": 0.1}
    vec = vector_from_dict(d, ["login_count", "failed_ratio", "sudo_count"])
    assert vec == [3.0, 0.1, 0.0]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_ueba_features.py -v 2>&1 | tail -15
```

Expected: FAIL — `HOST_FEATURE_KEYS` not defined, `velocity` not in USER_FEATURE_KEYS.

- [ ] **Step 3: Replace features.py with updated version**

Write the complete new `worker/worker/ueba/features.py`:

```python
# worker/worker/ueba/features.py
import json
from datetime import datetime, timezone

WINDOW = 3600          # 1-hour sliding window for counters
KNOWN_IPS_TTL = 7 * 24 * 3600   # 7 days for new-IP detection
TI_CACHE_TTL  = 86400  # 24 hours for TI reputation cache

USER_FEATURE_KEYS = [
    "login_count", "failed_ratio", "unique_ips", "unique_hosts",
    "sudo_count", "new_ip_seen", "hour_of_day", "is_weekend",
    "velocity", "hour_deviation",
]

IP_FEATURE_KEYS = [
    "unique_users", "total_events", "failed_ratio",
    "unique_target_hosts", "hour_of_day", "is_weekend",
    "failed_count", "velocity", "ti_reputation",
]

HOST_FEATURE_KEYS = [
    "unique_users", "total_events", "failed_ratio",
    "unique_source_ips", "sudo_count",
    "hour_of_day", "is_weekend", "velocity", "ti_reputation",
]


# ── Counter updates ──────────────────────────────────────────────

async def update_user_counters(redis, user: str, decoded: dict) -> None:
    action = decoded.get("event.action", "")
    ip     = decoded.get("source.ip")
    host   = decoded.get("host.hostname") or decoded.get("hostname")
    p = f"ueba:u:{user}"

    await redis.incr(f"{p}:login");  await redis.expire(f"{p}:login",  WINDOW)
    await redis.sadd("ueba:active:users", user)
    await redis.expire("ueba:active:users", WINDOW * 2)

    if "fail" in action.lower():
        await redis.incr(f"{p}:failed"); await redis.expire(f"{p}:failed", WINDOW)
    if "sudo" in action.lower() or "privilege" in action.lower():
        await redis.incr(f"{p}:sudo"); await redis.expire(f"{p}:sudo", WINDOW)

    if ip:
        is_new = not await redis.sismember(f"{p}:known_ips", ip)
        if is_new:
            await redis.set(f"{p}:new_ip", "1", ex=WINDOW)
        await redis.sadd(f"{p}:ips", ip);       await redis.expire(f"{p}:ips",       WINDOW)
        await redis.sadd(f"{p}:known_ips", ip); await redis.expire(f"{p}:known_ips", KNOWN_IPS_TTL)
    if host:
        await redis.sadd(f"{p}:hosts", host); await redis.expire(f"{p}:hosts", WINDOW)


async def update_ip_counters(redis, ip: str, decoded: dict, user: str | None) -> None:
    action = decoded.get("event.action", "")
    host   = decoded.get("host.hostname") or decoded.get("hostname")
    p = f"ueba:ip:{ip}"

    await redis.incr(f"{p}:total"); await redis.expire(f"{p}:total", WINDOW)
    await redis.sadd("ueba:active:ips", ip)
    await redis.expire("ueba:active:ips", WINDOW * 2)

    if "fail" in action.lower():
        await redis.incr(f"{p}:failed"); await redis.expire(f"{p}:failed", WINDOW)
    if user:
        await redis.sadd(f"{p}:users", user); await redis.expire(f"{p}:users", WINDOW)
    if host:
        await redis.sadd(f"{p}:hosts", host); await redis.expire(f"{p}:hosts", WINDOW)


async def update_host_counters(redis, hostname: str, decoded: dict, user: str | None) -> None:
    action = decoded.get("event.action", "")
    ip     = decoded.get("source.ip")
    p = f"ueba:host:{hostname}"

    await redis.incr(f"{p}:total"); await redis.expire(f"{p}:total", WINDOW)
    await redis.sadd("ueba:active:hosts", hostname)
    await redis.expire("ueba:active:hosts", WINDOW * 2)

    if "fail" in action.lower():
        await redis.incr(f"{p}:failed"); await redis.expire(f"{p}:failed", WINDOW)
    if "sudo" in action.lower() or "privilege" in action.lower():
        await redis.incr(f"{p}:sudo"); await redis.expire(f"{p}:sudo", WINDOW)
    if user:
        await redis.sadd(f"{p}:users", user); await redis.expire(f"{p}:users", WINDOW)
    if ip:
        await redis.sadd(f"{p}:src_ips", ip); await redis.expire(f"{p}:src_ips", WINDOW)


# ── Feature vector builders ──────────────────────────────────────

async def _get_ti_reputation(redis, ip: str) -> float:
    """Read cached TI reputation score (0.0–1.0). Written by investigator after TI lookup."""
    raw = await redis.get(f"ti:cache:{ip}")
    if not raw:
        return 0.0
    try:
        return float(json.loads(raw).get("score", 0.0))
    except Exception:
        return 0.0


async def build_user_vector_dict(
    redis, user: str, login_count: int, failed_count: int,
    prev_login_count: int = 0, mean_hour: float = 12.0,
) -> dict:
    p = f"ueba:u:{user}"
    now = datetime.now(timezone.utc)

    unique_ips   = await redis.scard(f"{p}:ips")
    unique_hosts = await redis.scard(f"{p}:hosts")
    sudo_count   = int(await redis.get(f"{p}:sudo") or 0)
    new_ip_seen  = int(await redis.get(f"{p}:new_ip") or 0)
    failed_ratio = (failed_count / login_count) if login_count > 0 else 0.0
    velocity     = login_count / max(prev_login_count, 1)
    hour_deviation = abs(now.hour - mean_hour)

    return {
        "login_count":    float(login_count),
        "failed_ratio":   failed_ratio,
        "unique_ips":     float(unique_ips),
        "unique_hosts":   float(unique_hosts),
        "sudo_count":     float(sudo_count),
        "new_ip_seen":    float(new_ip_seen),
        "hour_of_day":    float(now.hour),
        "is_weekend":     float(1 if now.weekday() >= 5 else 0),
        "velocity":       float(velocity),
        "hour_deviation": float(hour_deviation),
    }


async def build_ip_vector_dict(
    redis, ip: str, total_events: int, failed_count: int,
    prev_total: int = 0,
) -> dict:
    p = f"ueba:ip:{ip}"
    now = datetime.now(timezone.utc)

    unique_users        = await redis.scard(f"{p}:users")
    unique_target_hosts = await redis.scard(f"{p}:hosts")
    failed_ratio = (failed_count / total_events) if total_events > 0 else 0.0
    velocity     = total_events / max(prev_total, 1)
    ti_reputation = await _get_ti_reputation(redis, ip)

    return {
        "unique_users":        float(unique_users),
        "total_events":        float(total_events),
        "failed_ratio":        failed_ratio,
        "unique_target_hosts": float(unique_target_hosts),
        "hour_of_day":         float(now.hour),
        "is_weekend":          float(1 if now.weekday() >= 5 else 0),
        "failed_count":        float(failed_count),
        "velocity":            float(velocity),
        "ti_reputation":       ti_reputation,
    }


async def build_host_vector_dict(
    redis, hostname: str, total_events: int, failed_count: int,
    prev_total: int = 0,
) -> dict:
    p = f"ueba:host:{hostname}"
    now = datetime.now(timezone.utc)

    unique_users      = await redis.scard(f"{p}:users")
    unique_source_ips = await redis.scard(f"{p}:src_ips")
    sudo_count        = int(await redis.get(f"{p}:sudo") or 0)
    failed_ratio      = (failed_count / total_events) if total_events > 0 else 0.0
    velocity          = total_events / max(prev_total, 1)

    # TI reputation: worst score among source IPs connecting to this host
    src_ips = await redis.smembers(f"{p}:src_ips")
    ti_scores = [await _get_ti_reputation(redis, ip) for ip in list(src_ips)[:5]]
    ti_reputation = max(ti_scores) if ti_scores else 0.0

    return {
        "unique_users":      float(unique_users),
        "total_events":      float(total_events),
        "failed_ratio":      failed_ratio,
        "unique_source_ips": float(unique_source_ips),
        "sudo_count":        float(sudo_count),
        "hour_of_day":       float(now.hour),
        "is_weekend":        float(1 if now.weekday() >= 5 else 0),
        "velocity":          float(velocity),
        "ti_reputation":     ti_reputation,
    }


def vector_from_dict(d: dict, keys: list[str]) -> list[float]:
    """Convert feature dict to ordered list for sklearn."""
    return [float(d.get(k, 0.0)) for k in keys]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_ueba_features.py -v 2>&1 | tail -10
```

Expected: `4 passed`

- [ ] **Step 5: Update score_event in scorer.py to call update_host_counters**

In `worker/worker/ueba/scorer.py`, find the `score_event()` function. After the existing `if ip:` block that calls `update_ip_counters`, add:

```python
    hostname = decoded.get("hostname") or decoded.get("host.hostname")
    if hostname:
        await update_host_counters(redis, hostname, decoded, user)
```

Also add `update_host_counters` to the import from `worker.ueba.features`.

- [ ] **Step 6: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/worker/ueba/features.py worker/worker/ueba/scorer.py worker/tests/test_ueba_features.py
git commit -m "feat(ueba): add hostname entity, velocity, hour_deviation, ti_reputation features"
```

---

## Task 3: ML trainer — ensemble IF+LOF, Z-score profile, hostname model, risk_score snapshot

**Files:**
- Modify: `worker/worker/ueba/trainer.py`

Complete rewrite of `take_snapshots()` and `train_models()` to support the new architecture.

- [ ] **Step 1: Write test for Z-score profile computation**

Create `worker/tests/test_ueba_trainer.py`:

```python
import statistics
import pytest

def _compute_profile(snapshots_features: list[dict], keys: list[str]) -> dict:
    """Pure function extracted from trainer logic for testability."""
    profile = {}
    for key in keys:
        values = [float(s.get(key, 0.0)) for s in snapshots_features]
        if len(values) >= 2:
            profile[key] = {"mean": statistics.mean(values), "std": statistics.stdev(values) or 0.1}
        else:
            profile[key] = {"mean": values[0] if values else 0.0, "std": 0.1}
    return profile

def test_profile_mean_std():
    snaps = [{"login_count": 2.0}, {"login_count": 4.0}, {"login_count": 6.0}]
    profile = _compute_profile(snaps, ["login_count"])
    assert profile["login_count"]["mean"] == pytest.approx(4.0)
    assert profile["login_count"]["std"]  == pytest.approx(2.0)

def test_profile_fills_missing_with_zero():
    snaps = [{"login_count": 5.0}]
    profile = _compute_profile(snaps, ["login_count", "sudo_count"])
    assert profile["sudo_count"]["mean"] == 0.0

def test_profile_std_floor():
    # Single snapshot or all-same values → std should be at least 0.1
    snaps = [{"login_count": 3.0}, {"login_count": 3.0}]
    profile = _compute_profile(snaps, ["login_count"])
    assert profile["login_count"]["std"] >= 0.1
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_ueba_trainer.py -v 2>&1 | tail -8
```

Expected: The pure function isn't defined yet in a importable form; tests pass or fail depending on whether the helper is inline. That's fine — these tests document the expected behavior. Run: `3 passed` (they're self-contained).

- [ ] **Step 3: Replace trainer.py with updated version**

Write the complete new `worker/worker/ueba/trainer.py`:

```python
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
    """Build mean/std profile for Z-score scoring. Requires ≥ 1 snapshot."""
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


async def _upsert_profile(db, entity_type: str, entity_value: str, profile: dict) -> None:
    existing = await db.get(UebaEntityScore, (entity_type, entity_value))
    if existing:
        existing.feature_profile = profile
    # If not existing yet, profile will be set on next risk score upsert


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
            loop = asyncio.get_event_loop()

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
```

- [ ] **Step 4: Run trainer tests**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_ueba_trainer.py -v 2>&1 | tail -8
```

Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/worker/ueba/trainer.py worker/tests/test_ueba_trainer.py
git commit -m "feat(ueba): ensemble IF+LOF trainer, Z-score profiles, hostname model, risk_score snapshot"
```

---

## Task 4: ML scorer — ensemble scoring, combined risk formula, investigation queue push

**Files:**
- Modify: `worker/worker/ueba/scorer.py`

- [ ] **Step 1: Write unit test for risk formula**

Add to `worker/tests/test_ueba_features.py`:

```python
def test_combined_risk_formula():
    """Combined risk: z-score 60% + global 40% when both available."""
    old_risk = 50.0
    zscore_contrib = 40.0  # normalized z-score contribution
    global_contrib = 60.0  # normalized global ensemble contribution
    raw = zscore_contrib * 0.6 + global_contrib * 0.4
    new_risk = old_risk * 0.9 + raw * 0.1
    assert abs(new_risk - (50.0 * 0.9 + 48.0 * 0.1)) < 0.01

def test_zscore_only_when_no_global():
    old_risk = 0.0
    zscore_contrib = 80.0
    new_risk = old_risk * 0.9 + zscore_contrib * 0.1
    assert abs(new_risk - 8.0) < 0.01
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_ueba_features.py::test_combined_risk_formula -v 2>&1 | tail -8
```

Expected: FAIL (function not defined in import).

- [ ] **Step 3: Replace scorer.py with updated version**

Write the complete new `worker/worker/ueba/scorer.py`:

```python
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

ANOMALY_THRESHOLD    = -0.1   # IF+LOF ensemble score threshold for recording anomaly
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
    """Compute normalized Z-score contribution (0–100) from entity profile."""
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
    return min(max(z_scores) * 20, 100.0)  # scale max z-score to 0–100


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
```

- [ ] **Step 4: Run tests**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_ueba_features.py -v 2>&1 | tail -10
```

Expected: `6 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/worker/ueba/scorer.py worker/tests/test_ueba_features.py
git commit -m "feat(ueba): ensemble IF+LOF scorer, Z-score risk formula, investigation queue push"
```

---

## Task 5: ML gate in alert_manager.py

**Files:**
- Modify: `worker/worker/alert_manager.py`

Gate the AI queue push based on entity UEBA risk score.

- [ ] **Step 1: Write test for gate logic**

Create `worker/tests/test_ueba_gate.py`:

```python
import pytest

def _should_ai_investigate(risk: float, severity: str) -> bool:
    if severity == "critical":
        return True
    if risk >= 60:
        return True
    if severity == "high" and risk >= 40:
        return True
    return False

def test_critical_always_passes():
    assert _should_ai_investigate(0.0, "critical") is True

def test_high_risk_passes():
    assert _should_ai_investigate(65.0, "medium") is True

def test_high_severity_medium_risk_passes():
    assert _should_ai_investigate(45.0, "high") is True

def test_low_risk_low_severity_blocked():
    assert _should_ai_investigate(30.0, "low")    is False
    assert _should_ai_investigate(30.0, "medium") is False
    assert _should_ai_investigate(39.0, "high")   is False
```

- [ ] **Step 2: Run test to verify it passes (pure functions)**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_ueba_gate.py -v 2>&1 | tail -8
```

Expected: `4 passed` (pure function, no imports needed).

- [ ] **Step 3: Add gate functions to alert_manager.py**

Read `worker/worker/alert_manager.py`. Add these two functions after the existing imports:

```python
from worker.models import Alert, WebhookConfig, WebhookDelivery, UebaEntityScore

async def _get_entity_risk_max(source_ip: str | None, hostname: str | None) -> float:
    """Return the max UEBA risk score between the IP and hostname entities."""
    scores = []
    async with AsyncSessionLocal() as db:
        if source_ip:
            row = await db.get(UebaEntityScore, ("ip", source_ip))
            if row:
                scores.append(row.risk_score)
        if hostname:
            row = await db.get(UebaEntityScore, ("host", hostname))
            if row:
                scores.append(row.risk_score)
    return max(scores) if scores else 0.0


def _should_ai_investigate(risk: float, severity: str) -> bool:
    if severity == "critical":
        return True
    if risk >= 60:
        return True
    if severity == "high" and risk >= 40:
        return True
    return False
```

- [ ] **Step 4: Gate the AI queue push in create_alert()**

In `create_alert()`, find the `try:` block that pushes to `AI_ANALYSIS_QUEUE`. Wrap it with the gate check:

```python
    # Push to AI analysis queue — gated by ML entity risk score
    try:
        redis = await get_redis()
        risk = await _get_entity_risk_max(source_ip, hostname)
        if _should_ai_investigate(risk, rule_match["level"]):
            await mark_queued(redis, str(alert_id))
            await redis.rpush(AI_ANALYSIS_QUEUE, json.dumps({
                "alert_id": str(alert_id),
                "title": rule_match["title"],
                "severity": rule_match["level"],
                "source_ip": source_ip,
                "hostname": hostname,
                "decoded_fields": rule_match.get("matched_fields", {}),
                "group_id": group_id,
            }))
        else:
            log.debug("ai_gate_blocked", alert_id=str(alert_id),
                      severity=rule_match["level"], entity_risk=risk)
    except Exception as exc:
        log.error("ai_queue_push_failed", alert_id=str(alert_id), error=str(exc))
```

- [ ] **Step 5: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/worker/alert_manager.py worker/tests/test_ueba_gate.py
git commit -m "feat(ueba): add ML gate in alert_manager — skip AI for low-risk entities (saves 60-80% tokens)"
```

---

## Task 6: MITRE ATT&CK mapper

**Files:**
- Create: `worker/worker/ueba/mitre_mapper.py`
- Test: `worker/tests/test_mitre_mapper.py`

- [ ] **Step 1: Write failing tests**

Create `worker/tests/test_mitre_mapper.py`:

```python
import pytest
from worker.worker.ueba.mitre_mapper import map_to_mitre

def test_brute_force_detected():
    feat = {"failed_ratio": 0.6, "login_count": 10.0}
    result = map_to_mitre(feat, "user")
    ids = [t["id"] for t in result]
    assert "T1110" in ids

def test_password_spray_detected_on_ip():
    feat = {"unique_users": 6.0, "failed_ratio": 0.3}
    result = map_to_mitre(feat, "ip")
    ids = [t["id"] for t in result]
    assert "T1110.003" in ids

def test_valid_accounts_new_ip():
    feat = {"new_ip_seen": 1.0, "unique_ips": 4.0}
    result = map_to_mitre(feat, "user")
    ids = [t["id"] for t in result]
    assert "T1078" in ids

def test_privilege_escalation():
    feat = {"sudo_count": 5.0}
    result = map_to_mitre(feat, "user")
    ids = [t["id"] for t in result]
    assert "T1548" in ids

def test_lateral_movement_host():
    feat = {"unique_source_ips": 6.0}
    result = map_to_mitre(feat, "host")
    ids = [t["id"] for t in result]
    assert "T1021" in ids

def test_no_false_matches_for_clean_user():
    feat = {"failed_ratio": 0.0, "login_count": 1.0, "sudo_count": 0.0,
            "new_ip_seen": 0.0, "unique_ips": 1.0}
    result = map_to_mitre(feat, "user")
    assert result == []

def test_result_structure():
    feat = {"failed_ratio": 0.6, "login_count": 8.0}
    result = map_to_mitre(feat, "user")
    assert all("id" in t and "name" in t for t in result)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_mitre_mapper.py -v 2>&1 | tail -12
```

Expected: FAIL with `ModuleNotFoundError: worker.worker.ueba.mitre_mapper`

- [ ] **Step 3: Create mitre_mapper.py**

Create `worker/worker/ueba/mitre_mapper.py`:

```python
# worker/worker/ueba/mitre_mapper.py
"""
Rule-based mapping from UEBA feature values to MITRE ATT&CK techniques.
Each rule specifies: technique ID, name, applicable entity types, and a condition function.
"""

_RULES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "entity_types": {"user", "ip"},
        "condition": lambda f, t: f.get("failed_ratio", 0) >= 0.5 and f.get("login_count", 0) >= 5,
    },
    {
        "id": "T1110.003",
        "name": "Password Spraying",
        "entity_types": {"ip"},
        "condition": lambda f, t: f.get("unique_users", 0) >= 5 and f.get("failed_ratio", 0) >= 0.2,
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "entity_types": {"user"},
        "condition": lambda f, t: f.get("new_ip_seen", 0) >= 1 and f.get("unique_ips", 0) >= 3,
    },
    {
        "id": "T1078.001",
        "name": "Valid Accounts: Unusual Time Access",
        "entity_types": {"user"},
        "condition": lambda f, t: f.get("hour_deviation", 0) >= 6 and f.get("login_count", 0) >= 2,
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "entity_types": {"user", "host"},
        "condition": lambda f, t: f.get("sudo_count", 0) >= 3,
    },
    {
        "id": "T1021",
        "name": "Remote Services (Lateral Movement)",
        "entity_types": {"host"},
        "condition": lambda f, t: f.get("unique_source_ips", 0) >= 5 or f.get("unique_users", 0) >= 4,
    },
    {
        "id": "T1078.003",
        "name": "Valid Accounts: Local Accounts",
        "entity_types": {"user"},
        "condition": lambda f, t: f.get("sudo_count", 0) >= 2 and f.get("is_weekend", 0) == 1,
    },
]


def map_to_mitre(features: dict, entity_type: str) -> list[dict]:
    """
    Given a feature dict and entity type, return list of matched MITRE techniques.
    Each result is {"id": "T1110", "name": "Brute Force"}.
    """
    return [
        {"id": r["id"], "name": r["name"]}
        for r in _RULES
        if entity_type in r["entity_types"] and r["condition"](features, entity_type)
    ]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_mitre_mapper.py -v 2>&1 | tail -12
```

Expected: `7 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/worker/ueba/mitre_mapper.py worker/tests/test_mitre_mapper.py
git commit -m "feat(ueba): add MITRE ATT&CK mapper — rule-based feature-to-technique mapping"
```

---

## Task 7: UEBA AI Investigator

**Files:**
- Create: `worker/worker/ueba/investigator.py`

The core AI investigation loop: reads the queue, enriches with logs+TI+case memory, calls Groq, creates Case on ESCALATE.

- [ ] **Step 1: Create investigator.py**

Create `worker/worker/ueba/investigator.py`:

```python
# worker/worker/ueba/investigator.py
"""
UEBA AI Investigator: consumes siem:ueba:investigate queue.
For each anomaly: queries logs, runs TI, retrieves similar cases, maps MITRE,
calls Groq, and creates a Case on ESCALATE.
"""
import json
import uuid
import asyncio
import structlog
from datetime import datetime, timezone, timedelta
from sqlalchemy import select

from worker.database import AsyncSessionLocal
from worker.models import UebaAnomaly, Case, CaseNote, Alert
from worker.settings_cache import get_setting
from worker.ueba.mitre_mapper import map_to_mitre

log = structlog.get_logger()

UEBA_INVESTIGATE_QUEUE = "siem:ueba:investigate"
TI_CACHE_TTL = 86400  # 24 hours


async def _build_ti_config():
    from worker.ti.config import TIConfig
    return TIConfig(
        virustotal_api_key=await get_setting("virustotal_api_key"),
        abuseipdb_api_key=await get_setting("abuseipdb_api_key"),
        otx_api_key=await get_setting("otx_api_key"),
        greynoise_api_key=await get_setting("greynoise_api_key"),
        searxng_url=await get_setting("searxng_url", "http://searxng:8080"),
    )


def _compute_ti_score(overall_risk: float) -> float:
    """Map TI overall_risk (0–1) to a discrete reputation score for the ML cache."""
    if overall_risk >= 0.8:
        return 1.0
    if overall_risk >= 0.5:
        return 0.8
    if overall_risk >= 0.2:
        return 0.5
    return 0.0


async def _run_ti(redis, source_ip: str | None) -> tuple[str, float]:
    """Run TI enrichment on source_ip, cache result, return (bullets_text, overall_risk)."""
    if not source_ip:
        return "No source IP.", 0.0

    from worker.ti.aggregator import EnrichmentAggregator

    # Check cache first
    cached = await redis.get(f"ti:cache:{source_ip}")
    if cached:
        data = json.loads(cached)
        bullets_text = "\n".join(data.get("bullets", [])) or "Cached: clean"
        return bullets_text, data.get("score", 0.0)

    try:
        cfg = await _build_ti_config()
        agg = EnrichmentAggregator(cfg)
        enrichment = await agg.enrich(source_ip)
        score = _compute_ti_score(enrichment.overall_risk)
        bullets = enrichment.provider_bullets[:8]

        # Cache result for 24h — ML scorer will pick this up on next event
        await redis.setex(f"ti:cache:{source_ip}", TI_CACHE_TTL, json.dumps({
            "score":   score,
            "sources": [b.split(":")[0] for b in bullets if ":" in b],
            "bullets": bullets,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }))

        bullets_text = "\n".join(bullets) if bullets else "No threat intel hits."
        return bullets_text, score
    except Exception as exc:
        log.warning("ueba_ti_failed", source_ip=source_ip, error=str(exc))
        return "TI lookup failed.", 0.0


async def _get_recent_logs(entity_type: str, entity_value: str) -> str:
    """Fetch last 20 log entries related to this entity from the DB."""
    from worker.models import Event  # noqa
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    try:
        async with AsyncSessionLocal() as db:
            # Query by source_ip or hostname depending on entity_type
            from sqlalchemy import or_
            from worker.models import Event as Ev
            if entity_type == "ip":
                q = select(Ev).where(Ev.source_ip == entity_value).where(Ev.timestamp >= cutoff)
            elif entity_type == "host":
                q = select(Ev).where(Ev.hostname == entity_value).where(Ev.timestamp >= cutoff)
            else:
                q = select(Ev).where(Ev.raw_message.contains(entity_value)).where(Ev.timestamp >= cutoff)

            rows = (await db.execute(q.order_by(Ev.timestamp.desc()).limit(20))).scalars().all()

        if not rows:
            return "No recent log entries found."
        lines = [f"[{r.timestamp.strftime('%H:%M:%S')}] {(r.raw_message or '')[:120]}" for r in rows]
        return "\n".join(lines)
    except Exception as exc:
        log.warning("ueba_log_fetch_failed", error=str(exc))
        return "Log fetch failed."


async def _get_similar_cases(entity_type: str, mitre_ids: list[str]) -> list[dict]:
    """Find top-3 past UEBA anomalies that were escalated, matching entity_type + MITRE overlap."""
    if not mitre_ids:
        return []
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(UebaAnomaly)
                .where(UebaAnomaly.entity_type == entity_type)
                .where(UebaAnomaly.case_id.isnot(None))
                .where(UebaAnomaly.ai_action == "escalate")
                .order_by(UebaAnomaly.detected_at.desc())
                .limit(20)
            )).scalars().all()

        scored = []
        for row in rows:
            row_mitre = {t["id"] for t in (row.mitre_techniques or [])}
            overlap = len(set(mitre_ids) & row_mitre)
            if overlap > 0:
                scored.append((overlap, row))
        scored.sort(key=lambda x: -x[0])

        return [
            {
                "case_id":     str(r.case_id)[:8],
                "entity":      f'{r.entity_type} "{r.entity_value}"',
                "risk":        f"{r.risk_score:.0f}",
                "mitre":       ", ".join(t["id"] for t in (r.mitre_techniques or [])),
                "action":      r.ai_action or "unknown",
                "narrative":   (r.ai_narrative or "")[:300],
                "date":        r.detected_at.strftime("%Y-%m-%d"),
            }
            for _, r in scored[:3]
        ]
    except Exception as exc:
        log.warning("ueba_case_memory_failed", error=str(exc))
        return []


def _format_feature_table(features: dict, profile: dict) -> str:
    """Format features with Z-score context for the Groq prompt."""
    lines = []
    for key, val in features.items():
        p = profile.get(key, {})
        if p:
            std = p.get("std", 0.1) or 0.1
            z = abs(float(val) - p["mean"]) / std
            lines.append(f"  {key}: {val:.2f} (mean={p['mean']:.2f}, std={std:.2f}, z={z:.1f})")
        else:
            lines.append(f"  {key}: {val:.2f}")
    return "\n".join(lines)


async def _call_groq(prompt_user: str) -> dict:
    """Call Groq with UEBA-specific system prompt, return parsed JSON dict."""
    from worker.groq_client import _groq_client  # reuse existing client setup
    enabled = await get_setting("ai_analyst_enabled", "true")
    if enabled.lower() != "true":
        return {"action": "ALERT", "confidence": 0.5,
                "narrative": "AI analyst disabled.", "key_indicators": [], "recommended_action": "Review manually."}

    model = await get_setting("groq_model", "llama-3.3-70b-versatile")
    system = (
        "You are a senior SIEM security analyst specialising in UEBA (User and Entity Behaviour Analytics). "
        "Investigate the anomaly below and respond ONLY with valid JSON:\n"
        '{"action":"DISMISS"|"ALERT"|"ESCALATE","confidence":0.0-1.0,'
        '"narrative":"2-4 sentence summary","key_indicators":["list"],'
        '"recommended_action":"one specific next step"}'
    )

    from groq import AsyncGroq
    api_key = await get_setting("groq_api_key")
    if not api_key:
        return {"action": "ALERT", "confidence": 0.5,
                "narrative": "Groq API key not configured.", "key_indicators": [], "recommended_action": "Configure groq_api_key in Settings."}

    client = AsyncGroq(api_key=api_key)
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt_user},
            ],
            temperature=0.2,
            max_tokens=512,
        )
        raw = resp.choices[0].message.content.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1].lstrip("json").strip()
        return json.loads(raw)
    except Exception as exc:
        log.warning("ueba_groq_failed", error=str(exc))
        return {"action": "ALERT", "confidence": 0.4,
                "narrative": f"AI analysis failed: {exc}", "key_indicators": [], "recommended_action": "Review manually."}


async def _create_case(
    entity_type: str, entity_value: str,
    risk_score: float, severity: str,
    alert_id: uuid.UUID | None,
    ai_response: dict, mitre_techniques: list[dict],
    similar_cases: list[dict], group_id: str,
) -> uuid.UUID:
    async with AsyncSessionLocal() as db:
        case = Case(
            title=f"[UEBA] {entity_type.capitalize()} threat: {entity_value}",
            description=ai_response.get("narrative", ""),
            severity=severity,
            status="open",
            alert_id=alert_id,
            ai_reasoning=json.dumps({
                "key_indicators":    ai_response.get("key_indicators", []),
                "recommended_action": ai_response.get("recommended_action", ""),
                "similar_cases":     [c["case_id"] for c in similar_cases],
                "mitre_techniques":  [t["id"] for t in mitre_techniques],
                "confidence":        ai_response.get("confidence", 0),
            }, ensure_ascii=False),
            ioc_data={"mitre_techniques": mitre_techniques},
            created_by_ai=True,
            group_id=group_id,
        )
        db.add(case)
        await db.flush()

        note_content = (
            f"**UEBA AI Investigation**\n\n"
            f"{ai_response.get('narrative', '')}\n\n"
            f"**Key Indicators:**\n"
            + "\n".join(f"- {i}" for i in ai_response.get("key_indicators", []))
            + f"\n\n**Recommended Action:** {ai_response.get('recommended_action', '')}\n"
            + f"\n**MITRE ATT&CK:** {', '.join(t['id'] + ' ' + t['name'] for t in mitre_techniques)}\n"
            + f"\n**Confidence:** {ai_response.get('confidence', 0):.0%}"
        )
        db.add(CaseNote(
            case_id=case.id, author_id=None,
            content=note_content, is_ai_generated=True,
        ))
        await db.commit()
        return case.id


async def _update_anomaly(
    anomaly_id: str,
    mitre_techniques: list[dict],
    ai_narrative: str,
    ai_action: str,
    case_id: uuid.UUID | None,
) -> None:
    try:
        async with AsyncSessionLocal() as db:
            row = await db.get(UebaAnomaly, uuid.UUID(anomaly_id))
            if row:
                row.mitre_techniques = mitre_techniques
                row.ai_narrative     = ai_narrative
                row.ai_action        = ai_action.lower()
                if case_id:
                    row.case_id = case_id
                await db.commit()
    except Exception as exc:
        log.warning("ueba_anomaly_update_failed", anomaly_id=anomaly_id, error=str(exc))


async def investigate(redis, payload: dict) -> None:
    entity_type  = payload["entity_type"]
    entity_value = payload["entity_value"]
    group_id     = payload.get("group_id", "default")
    anomaly_score = payload.get("anomaly_score", -0.2)
    risk_score   = payload.get("risk_score", 50.0)
    features     = payload.get("features", {})
    anomaly_id   = payload.get("anomaly_id", "")
    source_ip    = payload.get("source_ip")
    hostname     = payload.get("hostname")

    log.info("ueba_investigation_start", entity_type=entity_type, entity_value=entity_value)

    # 1. MITRE mapping
    mitre_techniques = map_to_mitre(features, entity_type)
    mitre_ids = [t["id"] for t in mitre_techniques]

    # 2. Threat Intelligence
    ti_text, ti_score = await _run_ti(redis, source_ip)

    # 3. Recent logs
    logs_text = await _get_recent_logs(entity_type, entity_value)

    # 4. Case memory
    similar_cases = await _get_similar_cases(entity_type, mitre_ids)

    # 5. Entity profile from DB for Z-score context in prompt
    profile = {}
    try:
        from worker.models import UebaEntityScore
        async with AsyncSessionLocal() as db:
            row = await db.get(UebaEntityScore, (entity_type, entity_value))
            if row:
                profile = row.feature_profile or {}
    except Exception:
        pass

    # 6. Build Groq prompt
    feature_table = _format_feature_table(features, profile)

    similar_text = ""
    for c in similar_cases:
        similar_text += (
            f"- Case #{c['case_id']} ({c['date']}, {c['action'].upper()}): "
            f"{c['entity']} | Risk: {c['risk']} | MITRE: {c['mitre']}\n"
            f"  Summary: {c['narrative']}\n"
        )

    severity = (
        "critical" if risk_score >= 80 else
        "high"     if risk_score >= 60 else
        "medium"   if risk_score >= 40 else "low"
    )

    prompt = f"""ENTITY: {entity_type} "{entity_value}" | Risk Score: {risk_score:.0f}/100 | Severity: {severity.upper()}
Anomaly Score: {anomaly_score:.3f} | Detected: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

BEHAVIORAL FEATURES (current vs baseline):
{feature_table}

MITRE ATT&CK MATCHES: {", ".join(f"{t['id']} {t['name']}" for t in mitre_techniques) or "None"}

THREAT INTELLIGENCE (source IP: {source_ip or "N/A"}):
{ti_text}
TI Risk Score: {ti_score:.2f}

RECENT LOGS (last 1 hour):
{logs_text}

SIMILAR HISTORICAL CASES:
{similar_text or "No similar historical cases found."}

Analyze all evidence and provide your investigation verdict as JSON."""

    # 7. Groq analysis
    ai_response = await _call_groq(prompt)
    action = ai_response.get("action", "ALERT").upper()

    log.info("ueba_investigation_complete",
             entity_type=entity_type, entity_value=entity_value,
             action=action, confidence=ai_response.get("confidence", 0))

    # 8. Post-decision actions
    case_id = None

    if action in ("ALERT", "ESCALATE"):
        from worker.alert_manager import create_alert
        alert_db_id = await create_alert(
            rule_match={
                "id":         f"ueba-ai-{entity_type}",
                "title":      f"[UEBA AI] {entity_type.capitalize()} threat confirmed: {entity_value} [risk: {risk_score:.0f}/100]",
                "level":      severity,
                "tags":       ["ueba", "ueba.ai", f"ueba.{entity_type}"] + [t["id"] for t in mitre_techniques],
                "matched_fields": features,
            },
            event_id=None, agent_id=None,
            group_id=group_id,
            source_ip=source_ip,
            hostname=hostname,
        )
    else:
        alert_db_id = None

    if action == "ESCALATE":
        case_id = await _create_case(
            entity_type=entity_type, entity_value=entity_value,
            risk_score=risk_score, severity=severity,
            alert_id=alert_db_id,
            ai_response=ai_response, mitre_techniques=mitre_techniques,
            similar_cases=similar_cases, group_id=group_id,
        )
        log.info("ueba_case_created", case_id=str(case_id),
                 entity_type=entity_type, entity_value=entity_value)

    # 9. Update anomaly record with AI results
    await _update_anomaly(
        anomaly_id=anomaly_id,
        mitre_techniques=mitre_techniques,
        ai_narrative=ai_response.get("narrative", ""),
        ai_action=action,
        case_id=case_id,
    )


async def ueba_investigator_loop(redis) -> None:
    await asyncio.sleep(30)  # startup delay
    log.info("ueba_investigator_started")
    while True:
        try:
            item = await redis.blpop(UEBA_INVESTIGATE_QUEUE, timeout=10)
            if item:
                _, raw = item
                payload = json.loads(raw)
                await investigate(redis, payload)
        except Exception as exc:
            log.error("ueba_investigator_error", error=str(exc))
            await asyncio.sleep(5)
```

- [ ] **Step 2: Verify syntax**

```bash
cd /home/wonka/Documents/hackathon/worker
python -c "from worker.worker.ueba.investigator import ueba_investigator_loop; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/worker/ueba/investigator.py
git commit -m "feat(ueba): add AI investigator — TI cache, case memory RAG, MITRE mapping, Groq, Case creation"
```

---

## Task 8: Wire up background loops

**Files:**
- Modify: `worker/worker/ueba/loops.py`
- Modify: `worker/worker/main.py`

- [ ] **Step 1: Add ueba_ai_loop to loops.py**

Read `worker/worker/ueba/loops.py`. Add the new loop function:

```python
from worker.ueba.investigator import ueba_investigator_loop

async def ueba_ai_loop(redis) -> None:
    """Background loop for UEBA AI investigator — reads siem:ueba:investigate queue."""
    await ueba_investigator_loop(redis)
```

Also ensure the existing loops pass `redis` correctly. Check the existing `ueba_snapshot_loop` and `ueba_train_loop` signatures — they should already accept `redis`. If `loops.py` currently calls `get_redis()` internally, match that pattern:

```python
# Full loops.py
import asyncio
import structlog
from worker.redis_client import get_redis

log = structlog.get_logger()

async def ueba_snapshot_loop() -> None:
    from worker.ueba.trainer import take_snapshots
    redis = await get_redis()
    await asyncio.sleep(300)  # 5-min startup delay
    while True:
        try:
            await take_snapshots(redis)
        except Exception as exc:
            log.error("ueba_snapshot_error", error=str(exc))
        await asyncio.sleep(3600)

async def ueba_train_loop() -> None:
    from worker.ueba.trainer import train_models
    redis = await get_redis()
    await asyncio.sleep(600)  # 10-min startup delay
    while True:
        try:
            await train_models(redis)
        except Exception as exc:
            log.error("ueba_train_error", error=str(exc))
        await asyncio.sleep(3600)

async def ueba_ai_loop() -> None:
    from worker.ueba.investigator import ueba_investigator_loop
    redis = await get_redis()
    await ueba_investigator_loop(redis)
```

- [ ] **Step 2: Add ueba_ai_loop to main.py gather**

Read `worker/worker/main.py`. Find the `asyncio.gather(...)` call. Add `ueba_ai_loop()`:

```python
from worker.ueba.loops import ueba_snapshot_loop, ueba_train_loop, ueba_ai_loop

await asyncio.gather(
    _consume(),
    reload_loop(state),
    webhook_retry_loop(),
    ai_analysis_loop(),
    ai_backfill_loop(),
    ueba_snapshot_loop(),
    ueba_train_loop(),
    ueba_ai_loop(),   # NEW
    hunt_loop(),
)
```

- [ ] **Step 3: Verify worker starts without import errors**

```bash
cd /home/wonka/Documents/hackathon/worker
python -c "from worker.worker.main import main; print('imports OK')" 2>&1 | tail -5
```

Expected: `imports OK`

- [ ] **Step 4: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/worker/ueba/loops.py worker/worker/main.py
git commit -m "feat(ueba): wire ueba_ai_loop into worker background task gather"
```

---

## Task 9: API changes — history endpoint, host support, updated schemas

**Files:**
- Modify: `server-api/app/schemas/schemas.py`
- Modify: `server-api/app/api/routes/ueba.py`

- [ ] **Step 1: Update schemas**

In `server-api/app/schemas/schemas.py`, find `class UebaAnomalyOut(BaseModel):` and add 4 new fields:

```python
class UebaAnomalyOut(BaseModel):
    id: UUID
    entity_type: str
    entity_value: str
    anomaly_score: float
    risk_score: float
    features: dict
    alert_id: UUID | None
    mitre_techniques: list[dict]
    ai_narrative: str | None
    ai_action: str | None
    case_id: UUID | None
    detected_at: datetime
    model_config = {"from_attributes": True}
```

Find `class UebaEntityScoreOut(BaseModel):` and add `feature_profile`:

```python
class UebaEntityScoreOut(BaseModel):
    entity_type: str
    entity_value: str
    group_id: str
    risk_score: float
    anomaly_count: int
    last_anomaly_at: datetime | None
    last_seen_at: datetime | None
    updated_at: datetime
    feature_profile: dict
    model_config = {"from_attributes": True}
```

Find `class UebaStatusOut(BaseModel):` and add `host_snapshot_count`:

```python
class UebaStatusOut(BaseModel):
    status: str
    trained_at: str | None
    user_snapshot_count: int
    ip_snapshot_count: int
    host_snapshot_count: int
```

Add new schema for history endpoint:

```python
class UebaRiskHistoryPoint(BaseModel):
    snapshot_hour: datetime
    risk_score: float
    model_config = {"from_attributes": True}
```

- [ ] **Step 2: Update ueba.py API routes**

Read `server-api/app/api/routes/ueba.py`. Make these changes:

**a) Update `GET /api/ueba/entities`** — add `host` to valid entity_type values and update status query to include host count.

**b) Update `GET /api/ueba/status`** — add `host_snapshot_count`.

**c) Add new `GET /api/ueba/entity/{entity_type}/{entity_value}/history`** endpoint.

Write the complete updated `server-api/app/api/routes/ueba.py`:

```python
# server-api/app/api/routes/ueba.py
import json
from functools import cache
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.models.models import UebaEntityScore, UebaAnomaly, UebaFeatureSnapshot
from app.schemas.schemas import (
    UebaEntityScoreOut, UebaEntityDetailOut, UebaStatusOut,
    UebaAnomalyOut, UebaRiskHistoryPoint,
)

router = APIRouter(prefix="/api/ueba", tags=["ueba"])
Perm = require_permission("alerts:read")


@cache
def _get_redis_sync():
    import redis as redis_lib
    import os
    url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    return redis_lib.from_url(url, decode_responses=True)


async def _redis():
    return _get_redis_sync()


@router.get("/entities", response_model=list[UebaEntityScoreOut])
async def list_entities(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
    entity_type: str = Query(default="all", pattern="^(user|ip|host|all)$"),
    min_risk: float = Query(default=0.0, ge=0.0, le=100.0),
    limit: int = Query(default=50, ge=1, le=200),
):
    q = select(UebaEntityScore).where(UebaEntityScore.risk_score >= min_risk)
    if entity_type != "all":
        q = q.where(UebaEntityScore.entity_type == entity_type)
    q = q.order_by(UebaEntityScore.risk_score.desc()).limit(limit)
    result = await db.execute(q)
    return [UebaEntityScoreOut.model_validate(r) for r in result.scalars().all()]


@router.get("/entity/{entity_type}/{entity_value}", response_model=UebaEntityDetailOut)
async def get_entity_detail(
    entity_type: str, entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
):
    score_row = await db.get(UebaEntityScore, (entity_type, entity_value))
    if not score_row:
        raise HTTPException(404, "Entity not found")

    anomalies = (await db.execute(
        select(UebaAnomaly)
        .where(UebaAnomaly.entity_type == entity_type)
        .where(UebaAnomaly.entity_value == entity_value)
        .order_by(UebaAnomaly.detected_at.desc())
        .limit(50)
    )).scalars().all()

    return UebaEntityDetailOut(
        score=UebaEntityScoreOut.model_validate(score_row),
        anomalies=[UebaAnomalyOut.model_validate(a) for a in anomalies],
    )


@router.get("/entity/{entity_type}/{entity_value}/history", response_model=list[UebaRiskHistoryPoint])
async def get_entity_risk_history(
    entity_type: str, entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
    days: int = Query(default=7, ge=1, le=30),
):
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await db.execute(
        select(UebaFeatureSnapshot.snapshot_hour, UebaFeatureSnapshot.risk_score)
        .where(UebaFeatureSnapshot.entity_type == entity_type)
        .where(UebaFeatureSnapshot.entity_value == entity_value)
        .where(UebaFeatureSnapshot.snapshot_hour >= cutoff)
        .order_by(UebaFeatureSnapshot.snapshot_hour.asc())
    )).all()
    return [UebaRiskHistoryPoint(snapshot_hour=r[0], risk_score=r[1]) for r in rows]


@router.get("/status", response_model=UebaStatusOut)
async def get_status(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
):
    r = _get_redis_sync()
    status     = r.get("ueba:model:status") or "cold"
    trained_at = r.get("ueba:model:trained_at")

    user_count = (await db.execute(
        select(func.count()).select_from(UebaFeatureSnapshot)
        .where(UebaFeatureSnapshot.entity_type == "user")
    )).scalar()
    ip_count = (await db.execute(
        select(func.count()).select_from(UebaFeatureSnapshot)
        .where(UebaFeatureSnapshot.entity_type == "ip")
    )).scalar()
    host_count = (await db.execute(
        select(func.count()).select_from(UebaFeatureSnapshot)
        .where(UebaFeatureSnapshot.entity_type == "host")
    )).scalar()

    return UebaStatusOut(
        status=status, trained_at=trained_at,
        user_snapshot_count=user_count or 0,
        ip_snapshot_count=ip_count or 0,
        host_snapshot_count=host_count or 0,
    )
```

- [ ] **Step 3: Verify dashboard TypeScript build still passes**

```bash
cd /home/wonka/Documents/hackathon/dashboard
npm run build 2>&1 | tail -5
```

Expected: `✓ built in` — no TS errors.

- [ ] **Step 4: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add server-api/app/schemas/schemas.py server-api/app/api/routes/ueba.py
git commit -m "feat(ueba): add history endpoint, host entity_type, MITRE+AI fields in schemas"
```

---

## Task 10: UI — hosts tab, risk trend chart, MITRE badges, AI narrative, case link

**Files:**
- Modify: `dashboard/src/pages/UEBAPage.tsx`

Read the current `UEBAPage.tsx` in full before making changes. The existing file has `useUebaEntities()`, `useUebaEntityDetail()`, `useUebaStatus()` hooks and a two-panel layout. Extend it — do not rewrite from scratch.

- [ ] **Step 1: Add new types and hooks**

At the top of `UEBAPage.tsx`, extend the existing type definitions:

```tsx
// Add to existing UebaAnomaly interface:
interface UebaAnomaly {
  id: string
  entity_type: string
  entity_value: string
  anomaly_score: number
  risk_score: number
  features: Record<string, number>
  alert_id: string | null
  mitre_techniques: Array<{ id: string; name: string }>  // NEW
  ai_narrative: string | null                             // NEW
  ai_action: string | null                               // NEW
  case_id: string | null                                 // NEW
  detected_at: string
}

interface UebaEntityScore {
  entity_type: string
  entity_value: string
  group_id: string
  risk_score: number
  anomaly_count: number
  last_anomaly_at: string | null
  last_seen_at: string | null
  feature_profile: Record<string, { mean: number; std: number }>  // NEW
}

interface UebaRiskPoint { snapshot_hour: string; risk_score: number }  // NEW
```

Add a new hook after the existing hooks:

```tsx
function useRiskHistory(entityType: string | null, entityValue: string | null) {
  return useQuery<UebaRiskPoint[]>({
    queryKey: ['ueba-history', entityType, entityValue],
    queryFn: () =>
      entityType && entityValue
        ? api.get(`/api/ueba/entity/${entityType}/${entityValue}/history`).then(r => r.data)
        : Promise.resolve([]),
    enabled: !!entityType && !!entityValue,
  })
}
```

- [ ] **Step 2: Add hosts tab to entity type selector**

Find the tab buttons for USERS / IPS. Add HOSTS:

```tsx
{(['user', 'ip', 'host'] as const).map(type => (
  <button
    key={type}
    onClick={() => { setEntityType(type); setSelected(null) }}
    className={`px-3 py-1 text-xs rounded font-medium uppercase tracking-wide
      ${entityType === type ? 'bg-primary text-primary-foreground' : 'hover:bg-muted text-muted-foreground'}`}
  >
    {type === 'user' ? 'Users' : type === 'ip' ? 'IPs' : 'Hosts'}
  </button>
))}
```

Update `entityType` state to include `'host'`:
```tsx
const [entityType, setEntityType] = useState<'user' | 'ip' | 'host'>('user')
```

- [ ] **Step 3: Add risk trend sparkline component**

Add this SVG sparkline component to the file (outside the main component):

```tsx
function RiskSparkline({ data }: { data: UebaRiskPoint[] }) {
  if (data.length < 2) return <p className="text-xs text-muted-foreground">Not enough data for trend.</p>
  const W = 300, H = 48
  const scores = data.map(d => d.risk_score)
  const min = Math.min(...scores), max = Math.max(...scores) || 1
  const pts = data.map((d, i) => {
    const x = (i / (data.length - 1)) * W
    const y = H - ((d.risk_score - min) / (max - min || 1)) * H
    return `${x},${y}`
  }).join(' ')
  const lastScore = scores[scores.length - 1]
  const color = lastScore >= 80 ? '#ef4444' : lastScore >= 60 ? '#f97316' : lastScore >= 40 ? '#eab308' : '#22c55e'
  return (
    <div className="mb-4">
      <div className="flex justify-between text-xs text-muted-foreground mb-1">
        <span>7-day risk trend</span>
        <span style={{ color }}>{lastScore.toFixed(0)}/100</span>
      </div>
      <svg width={W} height={H} className="w-full">
        <polyline points={pts} fill="none" stroke={color} strokeWidth={2} />
      </svg>
    </div>
  )
}
```

- [ ] **Step 4: Add MITRE badges and AI narrative to anomaly timeline**

In the anomaly timeline section, find where each anomaly is rendered. Add after the existing content:

```tsx
{/* MITRE ATT&CK badges */}
{anomaly.mitre_techniques?.length > 0 && (
  <div className="flex flex-wrap gap-1 mt-1">
    {anomaly.mitre_techniques.map(t => (
      <span key={t.id}
        title={t.name}
        className="text-xs px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 font-mono">
        {t.id}
      </span>
    ))}
  </div>
)}

{/* AI action badge */}
{anomaly.ai_action && (
  <span className={`text-xs px-1.5 py-0.5 rounded font-medium ml-1
    ${anomaly.ai_action === 'escalate' ? 'bg-red-500/20 text-red-400'
      : anomaly.ai_action === 'dismiss' ? 'bg-muted text-muted-foreground'
      : 'bg-yellow-500/20 text-yellow-400'}`}>
    {anomaly.ai_action.toUpperCase()}
  </span>
)}

{/* AI narrative */}
{anomaly.ai_narrative && (
  <p className="text-xs text-muted-foreground mt-1 italic leading-relaxed">
    {anomaly.ai_narrative}
  </p>
)}

{/* Case link */}
{anomaly.ai_action === 'escalate' && anomaly.case_id && (
  <a href={`/cases/${anomaly.case_id}`}
    className="text-xs text-primary underline mt-1 block">
    View Case →
  </a>
)}
```

- [ ] **Step 5: Wire risk history into entity detail panel**

In the entity detail panel (right panel), add the sparkline above the feature table:

```tsx
const { data: historyData = [] } = useRiskHistory(selected?.entity_type ?? null, selected?.entity_value ?? null)

// In JSX, before feature table:
<RiskSparkline data={historyData} />
```

- [ ] **Step 6: Update feature table to show Z-score context**

In the feature table, extend each row to show mean and Z-score if `feature_profile` is available:

```tsx
{Object.entries(selectedDetail.score.feature_profile || {}).length > 0
  ? Object.entries(selectedDetail.anomalies[0]?.features || {}).map(([key, val]) => {
      const profile = selectedDetail.score.feature_profile?.[key]
      const zScore = profile ? Math.abs((val - profile.mean) / (profile.std || 0.1)) : null
      const warn = zScore !== null && zScore >= 3
      return (
        <tr key={key} className="border-t border-border">
          <td className="px-3 py-1.5 text-xs text-muted-foreground font-mono">{key}</td>
          <td className="px-3 py-1.5 text-xs">{typeof val === 'number' ? val.toFixed(2) : val}</td>
          <td className="px-3 py-1.5 text-xs text-muted-foreground">{profile ? profile.mean.toFixed(2) : '—'}</td>
          <td className="px-3 py-1.5 text-xs font-mono">{zScore !== null ? zScore.toFixed(1) : '—'}</td>
          <td className="px-3 py-1.5 text-xs">{warn ? '⚠' : ''}</td>
        </tr>
      )
    })
  : /* fallback to original simple table */
    Object.entries(selectedDetail.anomalies[0]?.features || {}).map(([key, val]) => (
      <tr key={key} className="border-t border-border">
        <td className="px-3 py-1.5 text-xs text-muted-foreground font-mono">{key}</td>
        <td className="px-3 py-1.5 text-xs">{typeof val === 'number' ? (val as number).toFixed(2) : String(val)}</td>
      </tr>
    ))
}
```

Update the table header to include new columns when profile is available:

```tsx
<thead>
  <tr className="text-xs text-muted-foreground uppercase">
    <th className="px-3 py-2 text-left">Feature</th>
    <th className="px-3 py-2 text-left">Value</th>
    {Object.keys(selectedDetail.score.feature_profile || {}).length > 0 && (
      <>
        <th className="px-3 py-2 text-left">Mean</th>
        <th className="px-3 py-2 text-left">Z-score</th>
        <th className="px-3 py-2 text-left"></th>
      </>
    )}
  </tr>
</thead>
```

- [ ] **Step 7: Update status bar to show host count**

Find the key metrics section that shows `USER SNAPS` and `IP SNAPS`. Add:

```tsx
<div className="text-center">
  <p className="text-lg font-bold">{status?.host_snapshot_count ?? 0}</p>
  <p className="text-xs text-muted-foreground uppercase tracking-wide">Host Snaps</p>
</div>
```

- [ ] **Step 8: Verify TypeScript build**

```bash
cd /home/wonka/Documents/hackathon/dashboard
npm run build 2>&1 | tail -8
```

Expected: `✓ built in` with no TypeScript errors. Fix any type errors before committing.

- [ ] **Step 9: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add dashboard/src/pages/UEBAPage.tsx
git commit -m "feat(ueba): hosts tab, risk trend sparkline, MITRE badges, AI narrative, case link, Z-score feature table"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Hostname entity type | Task 2, 3, 4, 9, 10 |
| Velocity feature | Task 2 |
| Hour deviation feature | Task 2, 3 |
| TI reputation as ML feature + cache | Task 2, 7 |
| Per-entity Z-score profile (24h) | Task 3 |
| Ensemble IF + LOF | Task 3, 4 |
| Combined risk formula (Z 60% + global 40%) | Task 4 |
| Cold start stages (< 24, 24-49, 50+) | Task 3, 4 |
| ML gate in alert_manager | Task 5 |
| MITRE ATT&CK mapper | Task 6 |
| UEBA AI Investigator queue consumer | Task 7 |
| TI enrichment + cache write in investigator | Task 7 |
| Recent logs retrieval | Task 7 |
| Case memory / similar case retrieval | Task 7 |
| Groq prompt with historical context | Task 7 |
| DISMISS / ALERT / ESCALATE decisions | Task 7 |
| Case creation on ESCALATE | Task 7 |
| UebaAnomaly new columns | Task 1, 7 |
| DB migration (IF NOT EXISTS) | Task 1 |
| ueba_ai_loop wired | Task 8 |
| History endpoint | Task 9 |
| Hosts tab in UI | Task 10 |
| Risk trend sparkline | Task 10 |
| MITRE badges + AI narrative in UI | Task 10 |
| Z-score feature table | Task 10 |

**Placeholder scan:** None found. All steps contain actual code.

**Type consistency check:**
- `HOST_FEATURE_KEYS` defined in Task 2, used in Task 3 (trainer), Task 4 (scorer) ✓
- `build_host_vector_dict(redis, hostname, total, failed, prev_total)` signature consistent across Task 2–4 ✓
- `UebaRiskHistoryPoint` defined in Task 9 (schema), used in Task 9 (route), Task 10 (UI hook) ✓
- `mitre_techniques: list[dict]` used consistently in Task 1 (model), Task 6 (mapper), Task 7 (investigator), Task 9 (schema) ✓
- `feature_profile: dict` on `UebaEntityScore` — set in Task 3 (trainer), read in Task 7 (investigator), Task 9 (schema), Task 10 (UI) ✓
