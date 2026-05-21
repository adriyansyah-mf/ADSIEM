# UEBA with Machine Learning — Design Spec

**Date:** 2026-05-21  
**Status:** Approved  

---

## Goal

Add User and Entity Behavior Analytics (UEBA) to the SIEM platform. Continuously profile the behavior of users and IPs using an Isolation Forest model. When behavior deviates significantly from baseline, create an Alert and update a cumulative risk score visible on a dedicated UEBA dashboard page.

---

## Architecture

```
Event processed by consumer.py
        │
        ▼
ueba/scorer.py.score_event(decoded_fields)
        │
        ├── Update Redis feature counters (sliding 1h window)
        ├── Load Isolation Forest model from Redis (in-memory cache, reload every 5 min)
        ├── Build feature vector for user + IP
        ├── Score both entities
        └── anomaly_score < -0.1?
                 ├── yes → create_alert() + upsert ueba_entity_scores + insert ueba_anomalies
                 └── no  → upsert ueba_entity_scores (last_seen_at, decay risk)

Background loops (asyncio, added to main.py gather):
  ueba_train_loop()   — retrain every 60 min
  ueba_snapshot_loop() — write hourly feature snapshots to DB every 60 min
```

---

## New Files

```
worker/worker/ueba/
├── __init__.py
├── features.py     # Redis counter helpers (increment, read, TTL management)
├── trainer.py      # Load snapshots → train IsolationForest → pickle to Redis
├── scorer.py       # Per-event: extract features, score, alert, update risk
└── loops.py        # ueba_train_loop() and ueba_snapshot_loop() coroutines

server-api/app/api/routes/ueba.py   # REST endpoints
dashboard/src/pages/UEBAPage.tsx
dashboard/src/hooks/useUeba.ts
dashboard/src/types/index.ts        # add UebaEntityScore, UebaAnomaly types
```

**Modified files:**
- `worker/worker/consumer.py` — call `await scorer.score_event(decoded)` after event saved
- `worker/worker/main.py` — add `ueba_train_loop()` and `ueba_snapshot_loop()` to gather
- `server-api/app/main.py` — register ueba router
- `db/init.sql` — add 3 new tables
- `dashboard/src/App.tsx` — add `/ueba` route
- `dashboard/src/components/Layout.tsx` — add UEBA nav item

---

## Database Schema

```sql
-- Training data: hourly feature snapshots per entity
CREATE TABLE ueba_feature_snapshots (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type    VARCHAR(20)  NOT NULL,   -- 'user' | 'ip'
    entity_value   VARCHAR(255) NOT NULL,
    group_id       VARCHAR(100) NOT NULL DEFAULT 'default',
    features       JSONB        NOT NULL,
    snapshot_hour  TIMESTAMPTZ  NOT NULL,   -- truncated to hour boundary
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_ueba_snap_unique ON ueba_feature_snapshots(entity_type, entity_value, snapshot_hour);
CREATE INDEX idx_ueba_snap_lookup ON ueba_feature_snapshots(entity_type, snapshot_hour DESC);

-- Live risk scores per entity (upserted each event)
CREATE TABLE ueba_entity_scores (
    entity_type    VARCHAR(20)  NOT NULL,
    entity_value   VARCHAR(255) NOT NULL,
    group_id       VARCHAR(100) NOT NULL DEFAULT 'default',
    risk_score     FLOAT        NOT NULL DEFAULT 0,   -- 0–100
    anomaly_count  INTEGER      NOT NULL DEFAULT 0,
    last_anomaly_at TIMESTAMPTZ,
    last_seen_at   TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (entity_type, entity_value)
);
CREATE INDEX idx_ueba_scores_risk ON ueba_entity_scores(risk_score DESC);

-- Individual anomaly events (timeline data)
CREATE TABLE ueba_anomalies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type    VARCHAR(20)  NOT NULL,
    entity_value   VARCHAR(255) NOT NULL,
    group_id       VARCHAR(100) NOT NULL DEFAULT 'default',
    anomaly_score  FLOAT        NOT NULL,   -- raw IF score, negative = more anomalous
    risk_score     FLOAT        NOT NULL,   -- risk_score at time of detection
    features       JSONB        NOT NULL,   -- feature vector that triggered anomaly
    alert_id       UUID         REFERENCES alerts(id) ON DELETE SET NULL,
    detected_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ueba_anom_entity ON ueba_anomalies(entity_type, entity_value, detected_at DESC);
```

---

## Redis Keys

| Key | Type | Purpose |
|-----|------|---------|
| `ueba:u:{user}:login` | STRING (INCR + EXPIRE 3600s) | Login event count this hour |
| `ueba:u:{user}:failed` | STRING (INCR + EXPIRE 3600s) | Failed login count this hour |
| `ueba:u:{user}:sudo` | STRING (INCR + EXPIRE 3600s) | Sudo/privilege escalation count |
| `ueba:u:{user}:ips` | SET (SADD + EXPIRE 3600s) | Unique source IPs this hour |
| `ueba:u:{user}:hosts` | SET (SADD + EXPIRE 3600s) | Unique hosts accessed this hour |
| `ueba:u:{user}:known_ips` | SET (no expire) | IPs seen in last 7 days (for new_ip detection) |
| `ueba:ip:{ip}:users` | SET (SADD + EXPIRE 3600s) | Unique users from this IP this hour |
| `ueba:ip:{ip}:total` | STRING (INCR + EXPIRE 3600s) | Total events from IP this hour |
| `ueba:ip:{ip}:failed` | STRING (INCR + EXPIRE 3600s) | Failed events from IP this hour |
| `ueba:ip:{ip}:hosts` | SET (SADD + EXPIRE 3600s) | Unique target hosts from IP |
| `ueba:model:user` | STRING (pickle bytes) | Trained IsolationForest for users |
| `ueba:model:ip` | STRING (pickle bytes) | Trained IsolationForest for IPs |
| `ueba:model:trained_at` | STRING | ISO timestamp of last successful training |
| `ueba:model:status` | STRING | `cold` \| `ready` |

---

## Feature Vectors

### User features (8 dimensions)

```python
[
    login_count,          # int — total login events in last 1h
    failed_ratio,         # float 0–1 — failed / total (0 if total=0)
    unique_ips,           # int — SCARD ueba:u:{user}:ips
    unique_hosts,         # int — SCARD ueba:u:{user}:hosts
    sudo_count,           # int
    new_ip_seen,          # 0 or 1 — any IP not in known_ips
    hour_of_day,          # int 0–23
    is_weekend,           # 0 or 1
]
```

### IP features (7 dimensions)

```python
[
    unique_users,         # int — SCARD ueba:ip:{ip}:users
    total_events,         # int — request velocity
    failed_ratio,         # float 0–1
    unique_target_hosts,  # int — lateral movement indicator
    hour_of_day,          # int 0–23
    is_weekend,           # 0 or 1
    failed_count,         # int — absolute count (brute force)
]
```

---

## Isolation Forest Config

```python
from sklearn.ensemble import IsolationForest

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # expect 5% of history to be anomalous
    random_state=42,
    n_jobs=-1,
)
```

**Training data minimum:** 50 snapshots per entity type. Below this threshold, model is not trained and `ueba:model:status = "cold"`. In cold state, scorer skips ML scoring (no false positives from insufficient data).

**Retraining:** Every 60 minutes. Reads all `ueba_feature_snapshots` from last 7 days. If training succeeds, pickles both models to Redis and sets `ueba:model:status = "ready"`.

---

## Scoring & Alert Logic

```python
# In scorer.py, called after each event
async def score_event(decoded: dict, group_id: str) -> None:
    user = decoded.get("user.name")
    ip   = decoded.get("source.ip")

    # Update Redis counters (always, even if model cold)
    if user:
        await _update_user_counters(user, decoded)
    if ip:
        await _update_ip_counters(ip, decoded, user)

    # Skip scoring if model not ready
    if not await _model_ready():
        return

    # Score user
    if user:
        vec = await _build_user_vector(user)
        score = _user_model.decision_function([vec])[0]   # negative = anomalous
        await _handle_score("user", user, score, vec, group_id, decoded)

    # Score IP
    if ip:
        vec = await _build_ip_vector(ip)
        score = _ip_model.decision_function([vec])[0]
        await _handle_score("ip", ip, score, vec, group_id, decoded)
```

**`_handle_score()` logic:**

```python
ANOMALY_THRESHOLD = -0.1   # tunable via platform_settings

new_risk = old_risk * 0.9 + (clamp(abs(score) * 100, 0, 100) * 0.1)

if score < ANOMALY_THRESHOLD:
    severity = "critical" if new_risk >= 80 else \
               "high"     if new_risk >= 60 else \
               "medium"   if new_risk >= 40 else "low"
    title = f"[UEBA] {entity_type.capitalize()} anomaly: {entity_value} [risk: {new_risk:.0f}/100]"
    await create_alert(rule_match={...}, ...)
    await _insert_ueba_anomaly(...)

await _upsert_entity_score(entity_type, entity_value, new_risk, ...)
```

Alert cooldown: do not re-alert same entity within 30 minutes (Redis key `ueba:cd:{type}:{value}` with TTL 1800s).

---

## API Endpoints

```
GET /api/ueba/entities
  Query params: entity_type (user|ip|all), min_risk (default 0), limit (default 50)
  Returns: list[UebaEntityScore] sorted by risk_score DESC

GET /api/ueba/entity/{entity_type}/{entity_value}
  Returns: UebaEntityScore + last 50 UebaAnomaly records for this entity

GET /api/ueba/status
  Returns: { status: "cold"|"ready", trained_at, user_snapshot_count, ip_snapshot_count }
```

All endpoints require `alerts:read` permission (existing).

---

## Response Schemas

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

class UebaAnomalyOut(BaseModel):
    id: UUID
    entity_type: str
    entity_value: str
    anomaly_score: float
    risk_score: float
    features: dict
    alert_id: UUID | None
    detected_at: datetime

class UebaStatusOut(BaseModel):
    status: str   # "cold" | "ready"
    trained_at: str | None
    user_snapshot_count: int
    ip_snapshot_count: int
```

---

## Dashboard (UEBAPage)

Two-panel layout (matches existing SOC theme — custom CSS vars, Rajdhani/Share Tech Mono fonts):

**Left panel — Risk Leaderboard**
- Two tabs: USERS / IPs
- Each row: entity value, risk score (0–100), colored bar (green/yellow/red), anomaly count
- Click row → load detail in right panel

**Right panel — Entity Detail**
- Entity name + risk score ring (same style as HygienePage)
- Current feature values with delta indicators (e.g. `failed_ratio: 0.82 ⚠`)
- Anomaly timeline: sparkline chart (last 7 days, 1 point per anomaly)
- Link to related alerts

**Header strip:**
- Model status badge: `COLD (collecting data)` or `READY (trained 14m ago)`
- Total high-risk entities count
- Total anomalies today

**Empty state:** "UEBA is collecting baseline data. Model trains automatically once 50 hourly snapshots are available (≈ 50 hours)."

---

## Worker Dependencies

Add to `worker/requirements.txt`:
```
scikit-learn>=1.4.0
numpy>=1.26.0
```

Both are pure Python wheels (no GPU required), ~25 MB combined.

---

## Cold Start Behavior

| Snapshots available | Behavior |
|---|---|
| < 50 | `status=cold` — counters accumulate, no scoring, no alerts |
| 50–200 | `status=ready` — model trains, scoring active, may have higher FP rate |
| > 200 | Stable baseline, low FP rate expected |

First alert is suppressed if `anomaly_count < 3` for that entity (avoid single-event false positives).

---

## Integration Points with Existing System

- **consumer.py**: single line added after event commit — `await ueba_scorer.score_event(decoded, group_id)`
- **alert_manager.py**: reused as-is, UEBA alerts go through same pipeline (webhook, AI analyst)
- **platform_settings**: add `ueba_enabled` (default `true`) and `ueba_anomaly_threshold` (default `-0.1`) to seed data
- **TI enrichment**: UEBA anomalies on IPs will also trigger existing TI enrichment via the AI analyst queue

---

## Out of Scope

- Host/agent entity tracking (future iteration)
- Supervised learning (requires labeled attack data)
- Geographic anomaly detection (requires GeoIP for every known IP)
- Peer group analysis (cluster users by role, flag deviations within group)
