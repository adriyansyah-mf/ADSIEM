# UEBA Enhanced: ML + AI Investigator Design

## Goal

Upgrade the existing UEBA system with three interrelated improvements:
(1) smarter ML via per-entity behavioral profiling + ensemble model,
(2) an ML gate that decides which alerts deserve AI investigation — saving 60–80% of Groq tokens,
(3) a UEBA-specific AI investigator that learns from historical cases and produces actionable Case reports with MITRE ATT&CK context.

## Architecture

```
Every event (consumer.py)
  → update Redis counters (always)
  → ML scoring: per-entity Z-score + global ensemble
  → if anomaly AND score < -0.2 AND risk ≥ 50:
       push to siem:ueba:investigate queue

Every alert (alert_manager.py — ALL sources: Sigma, Correlation, UEBA)
  → ML gate: lookup UEBA entity risk score
  → if critical OR (high + risk ≥ 40) OR risk ≥ 60:
       push to AI_ANALYSIS_QUEUE (existing analyst)
  → else: skip AI, save tokens

siem:ueba:investigate queue (new ueba_ai_loop)
  → query entity logs (last 1h from DB)
  → TI lookup on source IPs (existing TI engine)
  → check related entity anomalies (same IP → other users?)
  → map features to MITRE ATT&CK (rule-based)
  → retrieve top-3 similar historical cases (case memory)
  → Groq: generate narrative + decision (DISMISS / ALERT / ESCALATE)
  → if ESCALATE: create Case with full AI investigation report
```

---

## File Map

### New files
- `worker/worker/ueba/investigator.py` — AI investigator: queue consumer, orchestrator
- `worker/worker/ueba/mitre_mapper.py` — rule-based feature → ATT&CK technique mapping

### Modified files
- `worker/worker/ueba/features.py` — add hostname entity, velocity feature, `hour_deviation` feature
- `worker/worker/ueba/trainer.py` — ensemble IF + LOF, per-entity Z-score profile, risk_score in snapshot, hostname model
- `worker/worker/ueba/scorer.py` — add ensemble scoring (IF+LOF), push high-confidence anomalies (score < -0.2 AND risk ≥ 50) to `siem:ueba:investigate` queue. Normal anomaly alert creation (cooldown logic) remains unchanged — the investigator is additive, not a replacement.
- `worker/worker/ueba/loops.py` — add `ueba_ai_loop()`
- `worker/worker/main.py` — add `ueba_ai_loop()` to gather
- `worker/worker/models.py` — new columns: `UebaAnomaly.{mitre_techniques, ai_narrative, ai_action, case_id}`, `UebaEntityScore.feature_profile`, `UebaFeatureSnapshot.risk_score`
- `worker/worker/alert_manager.py` — add ML gate before AI_ANALYSIS_QUEUE push
- `server-api/app/models/models.py` — mirror new columns (for API reads)
- `server-api/app/schemas/schemas.py` — update `UebaAnomalyOut`, `UebaEntityScoreOut`
- `server-api/app/api/routes/ueba.py` — add `GET /api/ueba/entity/{type}/{value}/history`, support `entity_type=host`
- `dashboard/src/pages/UEBAPage.tsx` — hosts tab, risk trend chart, ATT&CK badges, AI narrative

---

## 1. ML Layer

### 1a. TI reputation as ML feature (feedback loop)

TI results influence ML scoring directly — not just AI context.

**TI reputation cache in Redis:**
Key: `ti:cache:{ip}` → JSON `{"score": 0.0–1.0, "sources": ["virustotal", "abuseipdb"], "cached_at": "..."}` with 24h TTL.

Score mapping:
- `0.0` = clean or unknown (no cache hit)
- `0.5` = suspicious (AbuseIPDB confidence 25–75, or 1–4 VT detections)
- `0.8` = malicious (AbuseIPDB confidence > 75, or ≥ 5 VT detections)
- `1.0` = confirmed IOC (OTX pulse hit OR GreyNoise malicious)

**Virtuous cycle:**
1. IP appears → ML scores with `ti_reputation = 0.0` (cache miss = neutral)
2. Anomaly detected → AI investigator does TI lookup → writes result to `ti:cache:{ip}`
3. Same IP appears again → ML reads cache → `ti_reputation = 0.8` → risk score higher → more likely to pass ML gate → more thorough investigation

**`ti_reputation` added to feature keys:**
- `IP_FEATURE_KEYS`: append `"ti_reputation"`
- `HOST_FEATURE_KEYS`: append `"ti_reputation"` (host's most malicious source IP in last window)

**In `build_ip_vector_dict()`:**
```python
ti_raw = await redis.get(f"ti:cache:{ip}")
ti_reputation = json.loads(ti_raw).get("score", 0.0) if ti_raw else 0.0
```

**In AI investigator (`investigator.py`)** — after TI lookups, write cache:
```python
score = _compute_ti_score(ti_results)  # maps VT/ABIPDB/OTX/GN results → 0.0–1.0
await redis.setex(f"ti:cache:{ip}", 86400, json.dumps({
    "score": score, "sources": list(ti_results.keys()), "cached_at": now.isoformat()
}))
```

This means TI reputation feeds back into ML on the next event from that IP — no additional API calls needed.

---

### 1b. New entity type: hostname

Track host-level behavior alongside user and IP.

**Redis key prefix:** `ueba:host:{hostname}:`

**Host features (8 dimensions):**
```
unique_users       — distinct users seen on this host in 1h window
total_events       — total events from this host
failed_ratio       — failed auth / total events
unique_source_ips  — distinct IPs connecting to this host
sudo_count         — privilege escalation events
hour_of_day        — current hour (0–23)
is_weekend         — 1 if Saturday/Sunday
velocity           — NEW: see below
```

**Redis keys added to `features.py`:**
```python
HOST_FEATURE_KEYS = [
    "unique_users", "total_events", "failed_ratio",
    "unique_source_ips", "sudo_count",
    "hour_of_day", "is_weekend", "velocity",
]
```

**`update_host_counters(redis, hostname, decoded)`** — mirrors `update_ip_counters` structure. Called from `score_event()` when `decoded.get("hostname")` is present.

**`build_host_vector_dict(redis, hostname, total, failed)`** — mirrors `build_ip_vector_dict`.

**Active set key:** `ueba:active:hosts` (TTL: `WINDOW * 2`)

### 1b. Velocity feature (all entity types)

Measures how fast an entity's event count is growing compared to the previous snapshot hour.

Stored in Redis as a ratio: `current_count / previous_snapshot_count`.

During `take_snapshots()`:
- Read previous snapshot from DB for this entity
- `velocity = current_login_count / max(prev_login_count, 1)` (ratio, not raw delta)
- Include `velocity` as additional feature in the snapshot features dict
- Feature keys updated: append `"velocity"` to `USER_FEATURE_KEYS`, `IP_FEATURE_KEYS`, `HOST_FEATURE_KEYS`

### 1c. Hour deviation feature (per-entity profiling)

Instead of raw `hour_of_day` (which the global model treats the same for everyone), compute how far the current hour is from this entity's typical active hours.

Computed during `take_snapshots()` using the entity's last 7 days of snapshots:
```python
historical_hours = [s.features["hour_of_day"] for s in past_snapshots]
mean_hour = statistics.mean(historical_hours) if historical_hours else 12.0
hour_deviation = abs(current_hour - mean_hour)
```

Store in snapshot features as `hour_deviation`. Keep `hour_of_day` as well (for the global model).

**Feature keys:** `USER_FEATURE_KEYS` gains `"hour_deviation"`, `"velocity"`. Remove raw `"hour_of_day"` from the per-entity Z-score profile computation but keep it in the global model vector.

### 1d. Per-entity Z-score profile (new, fast, starts at 24h)

Stored in `UebaEntityScore.feature_profile` (JSONB):
```json
{
  "login_count":   {"mean": 4.2, "std": 1.8},
  "failed_ratio":  {"mean": 0.05, "std": 0.03},
  "unique_ips":    {"mean": 1.1, "std": 0.4},
  ...
}
```

Computed during `take_snapshots()` from the last 7 days of snapshots for this entity:
```python
for key in FEATURE_KEYS:
    values = [s.features.get(key, 0.0) for s in past_snapshots]
    profile[key] = {"mean": mean(values), "std": stdev(values) or 0.1}
```

**Z-score anomaly score (per entity):**
```python
z_scores = [abs(current[k] - profile[k]["mean"]) / profile[k]["std"] for k in keys]
entity_zscore = max(z_scores)  # worst-case feature deviation
```

Available after 24 snapshots (24h), much lower than the 50-snapshot global model threshold.

### 1e. Ensemble: Isolation Forest + Local Outlier Factor

In `trainer.py`, train two models per entity type:

```python
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

if_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
lof_model = LocalOutlierFactor(n_neighbors=20, contamination=0.05, novelty=True)

await loop.run_in_executor(None, if_model.fit, X)
await loop.run_in_executor(None, lof_model.fit, X)
```

Both pickled and stored in Redis:
- `ueba:model:{entity_type}:if` — Isolation Forest
- `ueba:model:{entity_type}:lof` — LOF (novelty=True for predict-time scoring)

**Combined ensemble score:**
```python
if_score  = float(if_model.decision_function(vec)[0])   # negative = anomaly
lof_score = float(lof_model.decision_function(vec)[0])  # negative = anomaly
ensemble_score = (if_score * 0.5) + (lof_score * 0.5)
```

### 1f. Final risk score formula

```python
# Global ensemble contribution (available after 50 snapshots)
global_contrib = min(abs(ensemble_score) * 100, 100)

# Per-entity Z-score contribution (available after 24 snapshots)
zscore_contrib = min(entity_zscore * 20, 100)  # scale z-score to 0–100

# Combined (Z-score weighted higher — it's more personal)
if has_profile and has_global:
    raw = zscore_contrib * 0.6 + global_contrib * 0.4
elif has_profile:
    raw = zscore_contrib
else:
    raw = global_contrib

# Exponential moving average (existing — keeps continuity)
new_risk = old_risk * 0.9 + raw * 0.1
```

### 1g. Cold start stages

| Snapshots | Capability |
|---|---|
| < 24 | Counters only, no scoring |
| 24–49 | Per-entity Z-score active, global model cold |
| ≥ 50 | Full ensemble + per-entity Z-score combined |

### 1h. Training schedule (no change to cadence, expanded scope)

```
Every hour — snapshot phase (5-min startup delay):
  1. For each active user / IP / host:
     a. Build feature vector from Redis counters
     b. Compute hour_deviation and velocity from DB history
     c. Compute per-entity Z-score profile (mean/stddev per feature)
     d. Upsert to ueba_feature_snapshots (with risk_score column added)
     e. Update UebaEntityScore.feature_profile
  2. Prune snapshots > 8 days

Every hour — training phase (+10-min offset):
  1. Load all snapshots from last 7 days (user + ip + host)
  2. Train IF + LOF ensemble per entity type (3 types now)
  3. Store 6 models in Redis (if_user, lof_user, if_ip, lof_ip, if_host, lof_host)
  4. Recompute current risk scores for all entities
  5. Set ueba:model:status = "ready" | "cold"
```

---

## 2. ML Gate (alert_manager.py)

Every alert — from any source (Sigma rules, correlation engine, UEBA) — passes through this gate before the AI analysis queue.

**New function in `alert_manager.py`:**
```python
async def _should_ai_investigate(source_ip: str | None, hostname: str | None, severity: str) -> bool:
    if severity == "critical":
        return True
    risk = await _get_entity_risk_max(source_ip, hostname)
    if risk >= 60:
        return True
    if severity == "high" and risk >= 40:
        return True
    return False

async def _get_entity_risk_max(source_ip: str | None, hostname: str | None) -> float:
    """Returns the higher risk score between the IP and hostname entities."""
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
```

**Modified `create_alert()` — replace unconditional AI queue push:**
```python
# Before (pushes every alert):
await redis.rpush(AI_ANALYSIS_QUEUE, ...)

# After (gated):
if await _should_ai_investigate(source_ip, hostname, rule_match["level"]):
    await mark_queued(redis, str(alert_id))
    await redis.rpush(AI_ANALYSIS_QUEUE, json.dumps({...}))
```

**Token savings:** Only critical alerts and alerts from high-risk entities trigger AI investigation. Low-risk Sigma rule alerts (the majority) are processed without Groq calls.

---

## 3. UEBA AI Investigator

### 3a. Trigger criteria

In `scorer.py`, after `_handle_score()`, push to investigation queue when:
- `ensemble_score < -0.2` (stricter than the detection threshold of -0.1)
- AND `new_risk >= 50`
- AND entity not in investigation cooldown (`ueba:inv_cd:{type}:{value}` — 60-minute TTL)

```python
INVESTIGATE_THRESHOLD = -0.2
INVESTIGATE_RISK_MIN  = 50
INV_COOLDOWN_TTL      = 3600  # 1 hour

if ensemble_score < INVESTIGATE_THRESHOLD and new_risk >= INVESTIGATE_RISK_MIN:
    inv_cd_key = f"ueba:inv_cd:{entity_type}:{entity_value}"
    if not await redis.exists(inv_cd_key):
        await redis.setex(inv_cd_key, INV_COOLDOWN_TTL, "1")
        await redis.rpush("siem:ueba:investigate", json.dumps({
            "entity_type":  entity_type,
            "entity_value": entity_value,
            "group_id":     group_id,
            "anomaly_score": ensemble_score,
            "risk_score":   new_risk,
            "features":     feat_dict,
            "anomaly_id":   str(anomaly_db_id),
        }))
```

### 3b. MITRE ATT&CK mapping (`mitre_mapper.py`)

Rule-based mapping from feature values to ATT&CK techniques. Returns a list of matched technique dicts.

```python
TECHNIQUE_RULES = [
    {
        "id": "T1110", "name": "Brute Force",
        "condition": lambda f, t: f.get("failed_ratio", 0) >= 0.5 and f.get("login_count", 0) >= 5,
        "entity_types": ["user", "ip"],
    },
    {
        "id": "T1110.003", "name": "Password Spraying",
        "condition": lambda f, t: t == "ip" and f.get("unique_users", 0) >= 5,
        "entity_types": ["ip"],
    },
    {
        "id": "T1078", "name": "Valid Accounts",
        "condition": lambda f, t: f.get("new_ip_seen", 0) >= 1 and f.get("unique_ips", 0) >= 3,
        "entity_types": ["user"],
    },
    {
        "id": "T1548", "name": "Abuse Elevation Control Mechanism",
        "condition": lambda f, t: f.get("sudo_count", 0) >= 3,
        "entity_types": ["user", "host"],
    },
    {
        "id": "T1021", "name": "Remote Services (Lateral Movement)",
        "condition": lambda f, t: f.get("unique_users", 0) >= 4 or f.get("unique_source_ips", 0) >= 5,
        "entity_types": ["host"],
    },
    {
        "id": "T1078.001", "name": "Valid Accounts: Default Accounts",
        "condition": lambda f, t: (f.get("is_weekend", 0) == 1 or f.get("hour_deviation", 0) >= 6)
                                   and f.get("login_count", 0) >= 2,
        "entity_types": ["user"],
    },
]

def map_to_mitre(features: dict, entity_type: str) -> list[dict]:
    return [
        {"id": r["id"], "name": r["name"]}
        for r in TECHNIQUE_RULES
        if entity_type in r["entity_types"] and r["condition"](features, entity_type)
    ]
```

### 3c. Case memory retrieval

Before calling Groq, query top-3 similar historical cases:

```python
async def _get_similar_cases(
    entity_type: str, features: dict, mitre_ids: list[str], db
) -> list[dict]:
    # Query UebaAnomaly records that have a linked case, matching entity_type,
    # with overlapping MITRE techniques (JSONB containment or overlap)
    # Order by recency, limit 3
    rows = (await db.execute(
        select(UebaAnomaly)
        .where(UebaAnomaly.entity_type == entity_type)
        .where(UebaAnomaly.case_id.isnot(None))
        .where(UebaAnomaly.ai_action.in_(["escalate", "alert"]))
        .order_by(UebaAnomaly.detected_at.desc())
        .limit(20)  # fetch 20, filter by MITRE overlap in Python
    )).scalars().all()

    # Score by MITRE technique overlap
    scored = []
    for row in rows:
        row_mitre = {t["id"] for t in (row.mitre_techniques or [])}
        overlap = len(set(mitre_ids) & row_mitre)
        if overlap > 0:
            scored.append((overlap, row))
    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:3]]
```

Format each similar case for the Groq prompt:
```
Case #{case_id[:8]} ({detected_at.date()}, {ai_action.upper()}):
  Entity: {entity_type} "{entity_value}" | Risk: {risk_score:.0f}
  MITRE: {", ".join(mitre_ids)}
  AI summary: {ai_narrative[:300]}
```

### 3d. Groq prompt structure

```python
SYSTEM_PROMPT = """You are a senior SIEM security analyst specializing in UEBA 
(User and Entity Behavior Analytics). You investigate behavioral anomalies and 
decide whether they represent genuine threats requiring escalation.

You have access to: real-time behavioral features, threat intelligence, 
historical similar cases, and recent log entries. Be concise and actionable.

Respond with JSON:
{
  "action": "DISMISS" | "ALERT" | "ESCALATE",
  "confidence": 0.0–1.0,
  "narrative": "2–4 sentence investigation summary",
  "key_indicators": ["list of 2–4 specific suspicious observations"],
  "recommended_action": "specific next step for the analyst"
}"""

USER_PROMPT = f"""
ENTITY: {entity_type} "{entity_value}" | Risk Score: {risk_score:.0f}/100
Anomaly Score: {anomaly_score:.3f} | Detected: {now}

BEHAVIORAL FEATURES (current vs normal):
{feature_table}  ← formatted as "feature: current_value (mean: X, std: Y, z-score: Z)"

MITRE ATT&CK MATCHES: {mitre_list or "None"}

THREAT INTELLIGENCE:
{ti_results}  ← from existing TI engine (VT, AbuseIPDB, OTX, GreyNoise)

RECENT LOGS (last 1 hour, up to 20 entries):
{log_entries}

SIMILAR HISTORICAL CASES:
{similar_cases_text or "No similar cases found."}

Based on all evidence, provide your investigation verdict.
"""
```

### 3e. Post-decision actions

**DISMISS:** Update `UebaAnomaly.ai_action = "dismiss"`, `ai_narrative`, `mitre_techniques`. No alert, no case.

**ALERT:** Call existing `create_alert()` with UEBA context + MITRE tags. Update anomaly record with `ai_action = "alert"`, `alert_id`.

**ESCALATE:** Call `create_alert()`, then create a `Case` directly via DB (following pattern in `ai_analyst.py`):
```python
case = Case(
    title=f"[UEBA] {entity_type.capitalize()} threat: {entity_value}",
    description=ai_response["narrative"],
    severity=alert_severity,
    status="open",
    alert_id=alert_id,
    ai_reasoning=json.dumps({
        "key_indicators": ai_response["key_indicators"],
        "recommended_action": ai_response["recommended_action"],
        "similar_cases": [str(c.case_id) for c in similar_cases],
        "mitre_techniques": mitre_techniques,
        "confidence": ai_response["confidence"],
    }),
    created_by_ai=True,
    group_id=group_id,
)
```
Update `UebaAnomaly.case_id = case.id`, `ai_action = "escalate"`.

### 3f. Investigator loop (`investigator.py`)

```python
UEBA_INVESTIGATE_QUEUE = "siem:ueba:investigate"

async def ueba_investigator_loop(redis) -> None:
    await asyncio.sleep(30)  # startup delay
    while True:
        try:
            item = await redis.blpop(UEBA_INVESTIGATE_QUEUE, timeout=10)
            if item:
                payload = json.loads(item[1])
                await investigate(redis, payload)
        except Exception as exc:
            log.error("ueba_investigator_error", error=str(exc))
            await asyncio.sleep(5)
```

`investigate()` is the full orchestration: TI → logs → similar cases → MITRE → Groq → action.

---

## 4. Database Changes

### `UebaAnomaly` — new columns
```python
mitre_techniques = Column(JSONB, nullable=False, default=list)   # [{"id":"T1110","name":"Brute Force"}]
ai_narrative     = Column(Text)                                   # Groq-generated summary
ai_action        = Column(String(20))                            # "dismiss"|"alert"|"escalate"
case_id          = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="SET NULL"))
```

### `UebaEntityScore` — new column
```python
feature_profile = Column(JSONB, nullable=False, default=dict)
# {"login_count": {"mean": 4.2, "std": 1.8}, ...}
```

### `UebaFeatureSnapshot` — new column
```python
risk_score = Column(Float, nullable=False, default=0.0)
# Snapshot of entity's risk_score at this hour — used for trend chart
```

All table changes applied via `Base.metadata.create_all` on startup (existing pattern — no migrations needed for new nullable/default columns).

---

## 5. API Changes

### New endpoint: risk history for trend chart
```
GET /api/ueba/entity/{entity_type}/{entity_value}/history
Query params: days (int, default 7, max 30)
Returns: list[{snapshot_hour: str, risk_score: float}] ordered by snapshot_hour ASC
Permission: alerts:read
```

Queries `ueba_feature_snapshots` ordered by `snapshot_hour` for the entity, returning only `snapshot_hour` and `risk_score`.

### Updated endpoint: entities list
`GET /api/ueba/entities` — add support for `entity_type=host`.

### Updated schema: `UebaAnomalyOut`
Add: `mitre_techniques`, `ai_narrative`, `ai_action`, `case_id`.

### Updated schema: `UebaEntityScoreOut`
Add: `feature_profile`.

---

## 6. UI Changes (`UEBAPage.tsx`)

### New: Hosts tab
Entity type tabs: **USERS / IPs / HOSTS** (existing tabs + new Hosts).

### New: Risk trend chart (sparkline)
In the entity detail panel, above the feature table:
- Small SVG line chart, 7-day daily risk scores
- Data from `GET /api/ueba/entity/{type}/{value}/history`
- Uses `recharts` `LineChart` or a minimal SVG sparkline

### New: MITRE ATT&CK badges
In the anomaly timeline, show technique chips per anomaly:
```tsx
{anomaly.mitre_techniques.map(t => (
  <span key={t.id} className="text-xs px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 font-mono">
    {t.id}
  </span>
))}
```

### New: AI narrative section
Below MITRE badges in anomaly timeline:
```tsx
{anomaly.ai_narrative && (
  <p className="text-xs text-muted-foreground mt-1 italic">{anomaly.ai_narrative}</p>
)}
```

### New: Action badge + Case link
```tsx
{anomaly.ai_action === "escalate" && anomaly.case_id && (
  <Link to={`/cases/${anomaly.case_id}`} className="text-xs text-primary underline">
    View Case →
  </Link>
)}
```

### Updated: Feature table
Add Z-score column alongside raw value:
```
Feature       | Value | Mean  | Std  | Z-score | ⚠
failed_ratio  | 0.78  | 0.05  | 0.03 | 24.3    | ⚠
```

---

## 7. Error Handling

- **Groq unavailable:** Investigation fails gracefully — anomaly recorded without `ai_narrative`, alert still created via ML-only path. Log `ueba_groq_failed`.
- **TI engine timeout:** Skip TI section in prompt, continue investigation.
- **No similar cases:** Empty section in prompt — AI investigates without historical context.
- **Investigation queue overflow (> 500 items):** Log warning, drop new item (existing alert was already created by scorer, so nothing is lost — just no AI enrichment).
- **Model cold during gate check:** `_get_entity_risk_max` returns 0.0 — gate passes only `critical` severity. Safe default.

---

## 8. Token Budget

| Scenario | Before | After |
|---|---|---|
| Low-severity Sigma alert, unknown entity | AI call | **No AI call** |
| High-severity Sigma alert, low-risk entity | AI call | **No AI call** |
| Any alert, entity risk ≥ 60 | AI call | AI call (same) |
| Critical alert, any entity | AI call | AI call (same) |
| UEBA anomaly score < -0.2, risk ≥ 50 | Basic alert AI call | **Dedicated UEBA investigator** (richer context, direct Case) |
| Estimated overall savings | — | **60–80% fewer Groq calls** |
