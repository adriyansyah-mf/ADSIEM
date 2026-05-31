# Agentic SOC Analyst — Gap Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 6 gaps in the agentic SOC analyst loop: correct RAG verdict storage, confidence threshold gate, AI→SOAR bridge, AI-triggered threat hunting, immediate RAG re-index on case resolution, and AI-generated weekly report narrative.

**Architecture:** All changes are additive to existing modules. No new services. Tasks are ordered by dependency: RAG fix first (no deps), then threshold (no deps), then SOAR bridge + hunt trigger (both depend on enrichment result already available in ai_analyst.py), then re-index queue (cross-service via Redis), then report narrative (standalone Groq call in report_sender.py).

**Tech Stack:** Python asyncio, SQLAlchemy async, Redis, Groq API (via existing groq_client.py), pgvector (existing), FastAPI BackgroundTasks.

---

## File Map

| File | Change |
|------|--------|
| `worker/worker/rag_indexer.py` | Fix verdict to use `ioc_data->>'verdict'`; add Redis reindex queue drain |
| `worker/worker/soar_engine.py` | Add `ai_verdict`, `ai_confidence`, `ti_risk_score` params to `run_soar_playbooks()`; add `gte`/`lte` operators to `_matches_condition` |
| `worker/worker/ai_analyst.py` | Add confidence threshold gate; call `run_soar_playbooks()`; auto-enqueue ThreatHunt |
| `server-api/app/main.py` | Seed `ai_confidence_threshold` setting |
| `server-api/app/api/routes/cases.py` | Push case_id to Redis reindex queue on resolve/close |
| `worker/worker/report_sender.py` | Add `_generate_ai_narrative()` Groq call; inject into HTML digest |

---

## Task 1: Fix RAG verdict — use AI verdict from ioc_data, not case status

**Problem:** `rag_indexer.py` line 34 passes `verdict=row["status"]` ("resolved" / "closed") instead of the actual AI verdict stored in `cases.ioc_data->>'verdict'` ("escalate" / "create_case" / "false_positive" / "monitor"). Future RAG lookups get meaningless verdicts.

**Files:**
- Modify: `worker/worker/rag_indexer.py`

- [ ] **Step 1: Update the SQL query to extract the real AI verdict**

Open `worker/worker/rag_indexer.py`. Replace the existing `rag_index_loop` SQL and `index_case` call:

```python
# worker/worker/rag_indexer.py
"""Background loop: index resolved/closed cases that don't have embeddings yet."""
import asyncio
import structlog
from sqlalchemy import text
from worker.database import AsyncSessionLocal
from worker.rag import index_case, index_sop_document

log = structlog.get_logger()
INDEX_INTERVAL = 3600  # once per hour
REINDEX_QUEUE = "siem:rag:reindex"  # Redis list for immediate re-index requests


async def rag_index_loop() -> None:
    from worker.redis_client import get_redis
    await asyncio.sleep(60)  # let server start first
    redis = await get_redis()
    while True:
        try:
            # ── Drain immediate re-index queue first ──────────────────────────
            while True:
                item = await redis.lpop(REINDEX_QUEUE)
                if not item:
                    break
                case_id = item.decode() if isinstance(item, bytes) else item
                try:
                    async with AsyncSessionLocal() as db:
                        row = (await db.execute(text("""
                            SELECT c.id::text, c.title, c.description,
                                   COALESCE(c.ioc_data->>'verdict', c.status) AS verdict,
                                   c.group_id
                            FROM cases c
                            WHERE c.id = :case_id::uuid
                        """), {"case_id": case_id})).mappings().first()
                    if row:
                        await index_case(
                            case_id=row["id"],
                            title=row["title"],
                            description=row["description"],
                            verdict=row["verdict"],
                            group_id=row["group_id"],
                        )
                        log.info("rag_reindex_immediate", case_id=case_id, verdict=row["verdict"])
                except Exception as e:
                    log.error("rag_reindex_item_error", case_id=case_id, error=str(e))

            # ── Batch poll for unindexed resolved/closed cases ────────────────
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(text("""
                    SELECT c.id::text, c.title, c.description,
                           COALESCE(c.ioc_data->>'verdict', c.status) AS verdict,
                           c.group_id
                    FROM cases c
                    LEFT JOIN case_embeddings ce ON ce.case_id = c.id
                    WHERE c.status IN ('resolved', 'closed')
                      AND ce.case_id IS NULL
                    ORDER BY c.updated_at DESC
                    LIMIT 100
                """))).mappings().all()

            if rows:
                log.info("rag_indexer_batch", count=len(rows))
                for row in rows:
                    await index_case(
                        case_id=row["id"],
                        title=row["title"],
                        description=row["description"],
                        verdict=row["verdict"],
                        group_id=row["group_id"],
                    )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("rag_indexer_error", error=str(e))

        await asyncio.sleep(INDEX_INTERVAL)


SOP_INDEX_INTERVAL = 60


async def sop_index_loop() -> None:
    await asyncio.sleep(90)
    while True:
        try:
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(text("""
                    SELECT id::text, group_id, raw_text
                    FROM sop_documents
                    WHERE status = 'pending'
                    ORDER BY created_at ASC
                    LIMIT 10
                """))).mappings().all()

            for row in rows:
                await index_sop_document(
                    document_id=row["id"],
                    group_id=row["group_id"],
                    raw_text=row["raw_text"],
                )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("sop_indexer_error", error=str(e))

        await asyncio.sleep(SOP_INDEX_INTERVAL)
```

- [ ] **Step 2: Verify syntax**

```bash
cd /home/wonka/Documents/hackathon && python -m py_compile worker/worker/rag_indexer.py && echo "OK"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add worker/worker/rag_indexer.py
git commit -m "fix(rag): use actual AI verdict from ioc_data instead of case status; add Redis reindex queue drain"
```

---

## Task 2: Add ai_confidence_threshold setting and gate in ai_analyst.py

**Problem:** AI creates cases even when confidence is 0.1 (very uncertain). Setting lets ops teams tune the threshold.

**Files:**
- Modify: `server-api/app/main.py` (settings seed)
- Modify: `worker/worker/ai_analyst.py` (threshold gate)

- [ ] **Step 1: Add setting seed in server-api/app/main.py**

Find the block where settings are seeded (around line 41–48, the list of tuples with setting name/default/is_secret/description). Add one entry after `ai_analyst_enabled`:

```python
("ai_confidence_threshold", "0.0", False, "Minimum AI confidence (0.0-1.0) to create/escalate a case — notes always written regardless"),
```

The list looks like:
```python
    ("groq_api_key",           "",                          True,  "Groq API key ..."),
    ("groq_model",             "llama-3.3-70b-versatile",   False, "Groq model ID"),
    ("ai_analyst_enabled",     "true",                      False, "Enable automatic AI triage ..."),
    ("ai_confidence_threshold","0.0",                       False, "Minimum AI confidence (0.0-1.0) to create/escalate a case — notes always written regardless"),
    ("virustotal_api_key",     "",                          True,  "VirusTotal API key ..."),
```

- [ ] **Step 2: Add threshold gate in ai_analyst.py**

In `worker/worker/ai_analyst.py`, inside `analyze_and_maybe_create_case`, after the line that reads:

```python
    enabled = await get_setting("ai_analyst_enabled", "true")
    if enabled.lower() == "false":
        return
```

Add the threshold fetch (it will be used later after Groq returns confidence):

```python
    _threshold_str = await get_setting("ai_confidence_threshold", "0.0")
    try:
        _confidence_threshold = float(_threshold_str)
    except (ValueError, TypeError):
        _confidence_threshold = 0.0
```

Then, after the line:
```python
    verdict = analysis.get("verdict", "monitor")
    triage_notes = analysis.get("triage_notes", "")
    confidence = analysis.get("confidence", 0.0)
```

Add the gate — if below threshold and verdict is not "monitor" or "false_positive", downgrade to monitor so notes are still written but no case is created:

```python
    if confidence < _confidence_threshold and verdict not in ("monitor", "false_positive"):
        log.info("ai_low_confidence_downgrade",
                 alert_id=alert_id, confidence=confidence,
                 threshold=_confidence_threshold, original_verdict=verdict)
        verdict = "monitor"
```

- [ ] **Step 3: Verify syntax**

```bash
cd /home/wonka/Documents/hackathon && python -m py_compile worker/worker/ai_analyst.py server-api/app/main.py && echo "OK"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add worker/worker/ai_analyst.py server-api/app/main.py
git commit -m "feat(ai): add ai_confidence_threshold setting — gate case creation below configured confidence"
```

---

## Task 3: AI→SOAR bridge — add ai_verdict/ai_confidence/ti_risk to SOAR context

**Problem:** SOAR trigger context has no knowledge of AI verdict or TI risk score. Analysts can't write playbooks that react to AI decisions.

**Files:**
- Modify: `worker/worker/soar_engine.py`
- Modify: `worker/worker/ai_analyst.py`

- [ ] **Step 1: Add numeric operators and new fields to soar_engine.py**

In `worker/worker/soar_engine.py`, update `_matches_condition` to support `gte` and `lte` operators (needed for confidence/risk thresholds):

```python
def _matches_condition(cond: dict, ctx: dict) -> bool:
    field = cond.get("field", "")
    operator = cond.get("operator", "eq")
    value = cond.get("value")
    actual = ctx.get(field)

    if operator == "not_null":
        return actual is not None and actual != ""
    if actual is None:
        return operator == "neq"
    if operator == "eq":
        return str(actual).lower() == str(value).lower()
    if operator == "neq":
        return str(actual).lower() != str(value).lower()
    if operator == "gte":
        try:
            return float(actual) >= float(value)
        except (TypeError, ValueError):
            return False
    if operator == "lte":
        try:
            return float(actual) <= float(value)
        except (TypeError, ValueError):
            return False
    if operator == "in":
        if not isinstance(value, list):
            return False
        return str(actual).lower() in [str(v).lower() for v in value]
    if operator == "contains":
        if isinstance(actual, list):
            return any(str(value).lower() in str(item).lower() for item in actual)
        return str(value).lower() in str(actual or "").lower()
    return False
```

Then update `run_soar_playbooks` signature and ctx to accept and expose the new fields:

```python
async def run_soar_playbooks(
    alert_id: uuid.UUID,
    rule_match: dict,
    source_ip: str | None,
    hostname: str | None,
    user_name: str | None,
    group_id: str,
    ai_verdict: str | None = None,
    ai_confidence: float | None = None,
    ti_risk_score: float | None = None,
) -> None:
    ctx = {
        "severity":       rule_match.get("level", "medium"),
        "rule_title":     rule_match.get("title", ""),
        "tags":           rule_match.get("tags", []),
        "mitre_tags":     rule_match.get("mitre_tags", []),
        "source_ip":      source_ip,
        "hostname":       hostname,
        "user_name":      user_name,
        "group_id":       group_id,
        "ai_verdict":     ai_verdict,
        "ai_confidence":  ai_confidence,
        "ti_risk_score":  ti_risk_score,
    }
    # rest of function unchanged
```

- [ ] **Step 2: Call run_soar_playbooks from ai_analyst.py after verdict**

In `worker/worker/ai_analyst.py`, at the top of the file add import:

```python
from worker.soar_engine import run_soar_playbooks
from worker.models import Alert
```

Then in `analyze_and_maybe_create_case`, after step 4 (triage notes written) and before step 5 (update alert status), add:

```python
    # ── 4c. Fire SOAR playbooks with AI context ──────────────────────────────
    if alert_id:
        try:
            alert_uuid = uuid.UUID(alert_id)
            async with AsyncSessionLocal() as db:
                alert_obj = await db.get(Alert, alert_uuid)
                rule_match = {
                    "level": effective_severity,
                    "title": title,
                    "tags": decoded_fields.get("tags", []),
                    "mitre_tags": analysis.get("mitre_techniques", []),
                }
            asyncio.ensure_future(run_soar_playbooks(
                alert_id=alert_uuid,
                rule_match=rule_match,
                source_ip=source_ip,
                hostname=hostname,
                user_name=decoded_fields.get("user.name"),
                group_id=group_id,
                ai_verdict=verdict,
                ai_confidence=confidence,
                ti_risk_score=enrichment.overall_risk if enrichment else None,
            ))
        except Exception as exc:
            log.warning("ai_soar_dispatch_failed", alert_id=alert_id, error=str(exc))
```

- [ ] **Step 3: Verify syntax**

```bash
cd /home/wonka/Documents/hackathon && python -m py_compile worker/worker/soar_engine.py worker/worker/ai_analyst.py && echo "OK"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add worker/worker/soar_engine.py worker/worker/ai_analyst.py
git commit -m "feat(soar): add ai_verdict/ai_confidence/ti_risk_score to SOAR trigger context; call SOAR from AI analyst after triage"
```

---

## Task 4: AI auto-enqueue ThreatHunt for malicious IPs found during triage

**Problem:** AI analyst discovers malicious IPs during TI enrichment but never triggers a threat hunt. Hunting happens only when analysts manually request it.

**Files:**
- Modify: `worker/worker/ai_analyst.py`

- [ ] **Step 1: Add _maybe_enqueue_hunt helper in ai_analyst.py**

Add this function above `analyze_and_maybe_create_case`:

```python
async def _maybe_enqueue_hunt(source_ip: str, group_id: str) -> None:
    """Enqueue a ThreatHunt for source_ip if not already hunted in last 24h."""
    from worker.models import ThreatHunt
    window = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        async with AsyncSessionLocal() as db:
            existing = (await db.execute(
                select(ThreatHunt).where(
                    ThreatHunt.ioc_type == "ip",
                    ThreatHunt.ioc_value == source_ip,
                    ThreatHunt.group_id == group_id,
                    ThreatHunt.created_at >= window,
                )
            )).scalars().first()
            if existing:
                log.debug("hunt_skip_recent", source_ip=source_ip)
                return
            hunt = ThreatHunt(
                ioc_type="ip",
                ioc_value=source_ip,
                group_id=group_id,
            )
            db.add(hunt)
            await db.commit()
            log.info("hunt_enqueued_by_ai", source_ip=source_ip, group_id=group_id)
    except Exception as exc:
        log.warning("hunt_enqueue_failed", source_ip=source_ip, error=str(exc))
```

- [ ] **Step 2: Call _maybe_enqueue_hunt after TI enrichment in analyze_and_maybe_create_case**

In `analyze_and_maybe_create_case`, after the enrichment block (after `effective_severity = ...` block), add:

```python
    # ── 2b. Auto-enqueue threat hunt for malicious IPs ───────────────────────
    if source_ip and enrichment and enrichment.overall_risk > 0.5:
        asyncio.ensure_future(_maybe_enqueue_hunt(source_ip, group_id))
```

The `select` import is already present from the existing `_find_existing_open_case` function. Verify `ThreatHunt` is imported — add to imports at top of file if missing:

```python
from worker.models import Alert, AlertNote, Case, CaseNote, ThreatHunt
```

- [ ] **Step 3: Verify syntax**

```bash
cd /home/wonka/Documents/hackathon && python -m py_compile worker/worker/ai_analyst.py && echo "OK"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add worker/worker/ai_analyst.py
git commit -m "feat(ai): auto-enqueue ThreatHunt for malicious IPs (ti_risk > 0.5) found during triage"
```

---

## Task 5: Immediate RAG re-index when case is resolved or closed

**Problem:** When analyst resolves a case, RAG picks it up only on the next hourly poll. New alerts triaged in that window don't benefit from the just-resolved case as a similar-case example.

**Files:**
- Modify: `server-api/app/api/routes/cases.py`

Note: `rag_indexer.py` already handles the `siem:rag:reindex` Redis queue drain (added in Task 1).

- [ ] **Step 1: Add Redis push in cases.py update_case**

In `server-api/app/api/routes/cases.py`, add the Redis client import at the top:

```python
from server_api.app.core.redis import get_redis  # adjust import path if needed
```

Check the actual Redis import path used in this file already:

```bash
grep -n "redis\|get_redis" /home/wonka/Documents/hackathon/server-api/app/api/routes/cases.py | head -5
grep -rn "def get_redis\|async def get_redis" /home/wonka/Documents/hackathon/server-api/app/ | head -5
```

Use whatever import path is established. If no Redis client exists in server-api, use `aioredis` directly via the `REDIS_URL` from config.

Add a helper at the top of `cases.py`:

```python
async def _push_rag_reindex(case_id: str) -> None:
    """Push case_id to Redis reindex queue so worker indexes it immediately."""
    try:
        import aioredis
        from server_api.app.core.config import settings
        redis = await aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis.rpush("siem:rag:reindex", case_id)
        await redis.aclose()
    except Exception:
        pass  # non-critical: hourly loop will catch it
```

Then in `update_case`, after the `background.add_task(audit_log, ...)` line, add:

```python
    if body.status in ("resolved", "closed"):
        background.add_task(_push_rag_reindex, str(case_id))
```

- [ ] **Step 2: Check actual Redis import available in server-api**

```bash
grep -rn "REDIS_URL\|aioredis\|redis" /home/wonka/Documents/hackathon/server-api/app/core/config.py | head -5
grep -rn "import.*redis\|from.*redis" /home/wonka/Documents/hackathon/server-api/app/ | grep -v __pycache__ | head -10
```

Adjust the import in `_push_rag_reindex` to match what's already used in server-api.

- [ ] **Step 3: Verify syntax**

```bash
cd /home/wonka/Documents/hackathon && python -m py_compile server-api/app/api/routes/cases.py && echo "OK"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add server-api/app/api/routes/cases.py
git commit -m "feat(rag): push case_id to Redis reindex queue immediately when case is resolved or closed"
```

---

## Task 6: Weekly report with AI narrative via Groq

**Problem:** Weekly digest only shows alert counts. Management has no visibility into what AI analyst did, what campaigns were detected, and what to focus on next week.

**Files:**
- Modify: `worker/worker/report_sender.py`

- [ ] **Step 1: Add _generate_ai_narrative function to report_sender.py**

In `worker/worker/report_sender.py`, add these imports at the top if not already present:

```python
import json
from sqlalchemy import func, text
from worker.models import Case, CaseNote
```

Add the narrative generator function before `_send_digest`:

```python
async def _generate_ai_narrative(alerts: list, cutoff) -> str:
    """Ask Groq to write an executive summary of the week's security posture."""
    from worker.groq_client import _groq_post
    from worker.settings_cache import get_setting
    from worker.database import AsyncSessionLocal

    api_key = await get_setting("groq_api_key") or ""
    if not api_key:
        return ""

    # Gather AI verdict distribution from cases in the period
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                SELECT
                    ioc_data->>'verdict'         AS verdict,
                    COUNT(*)                     AS cnt,
                    array_agg(DISTINCT jsonb_array_elements_text(
                        CASE WHEN ioc_data->'mitre_techniques' IS NOT NULL
                             THEN ioc_data->'mitre_techniques'
                             ELSE '[]'::jsonb END
                    )) FILTER (WHERE ioc_data->'mitre_techniques' IS NOT NULL) AS mitre
                FROM cases
                WHERE created_at >= :cutoff
                  AND created_by_ai = TRUE
                GROUP BY ioc_data->>'verdict'
            """), {"cutoff": cutoff})).mappings().all()
            verdict_dist = {r["verdict"] or "unknown": r["cnt"] for r in rows}
            all_mitre = []
            for r in rows:
                if r["mitre"]:
                    all_mitre.extend(r["mitre"])
            top_mitre = list(dict.fromkeys(all_mitre))[:8]  # deduplicated, order preserved
    except Exception:
        verdict_dist = {}
        top_mitre = []

    severity_counts = {}
    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    prompt = f"""You are an AI SOC analyst writing a weekly executive security report.

Data for this week:
- Total alerts: {len(alerts)}
- Severity breakdown: {json.dumps(severity_counts)}
- AI verdict distribution: {json.dumps(verdict_dist)}
- MITRE ATT&CK techniques observed: {top_mitre}

Write a 3-paragraph executive summary in Indonesian:
1. Overview of the week's threat landscape
2. Key findings (campaigns detected, top techniques, notable patterns)
3. Recommended focus areas for the coming week

Keep it concise — max 200 words total. No bullet points, pure paragraphs."""

    model = await get_setting("groq_model", "llama-3.3-70b-versatile")
    try:
        result = await _groq_post(api_key, {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 400,
        })
        return result["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        log.warning("report_narrative_failed", error=str(exc))
        return ""
```

- [ ] **Step 2: Inject AI narrative into _send_digest HTML**

In `_send_digest`, call `_generate_ai_narrative` and inject it into the email HTML before the severity table. Change the function signature to accept `cutoff`:

```python
async def _send_digest(alerts: list, cutoff) -> None:
```

Add the narrative call at the start of `_send_digest` (after the enabled/host checks):

```python
    narrative = await _generate_ai_narrative(alerts, cutoff)
    narrative_html = ""
    if narrative:
        narrative_html = f"""
  <div style="background:#0a1628;border-left:3px solid #00d4ff;padding:16px;margin-bottom:20px;border-radius:4px">
    <h3 style="color:#00d4ff;margin:0 0 8px 0;font-size:13px">🤖 AI SOC Analyst — Weekly Summary</h3>
    <p style="color:#c8d8e8;font-size:13px;line-height:1.6;margin:0">{narrative.replace(chr(10), '<br>')}</p>
  </div>"""
```

In the HTML body template, add `{narrative_html}` before the `<h3>By Severity</h3>` section:

```python
    body = f"""<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:20px">
<div style="max-width:600px;margin:0 auto">
  <h2 style="color:#00d4ff">Weekly SIEM Digest</h2>
  <p style="color:#94a3b8">Period: last 7 days — {total} total alerts</p>
  {narrative_html}
  <h3 style="color:#94a3b8;font-size:14px">By Severity</h3>
  ...
```

- [ ] **Step 3: Update report_loop to pass cutoff to _send_digest**

In `report_loop`, find the call `await _send_digest(list(alerts))` and update to:

```python
                    await _send_digest(list(alerts), cutoff)
```

- [ ] **Step 4: Verify syntax**

```bash
cd /home/wonka/Documents/hackathon && python -m py_compile worker/worker/report_sender.py && echo "OK"
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add worker/worker/report_sender.py
git commit -m "feat(report): add AI-generated executive narrative to weekly digest via Groq"
```

---

## Phase Completion Criteria

- [ ] `python -m py_compile worker/worker/rag_indexer.py worker/worker/soar_engine.py worker/worker/ai_analyst.py worker/worker/report_sender.py server-api/app/api/routes/cases.py server-api/app/main.py` — all exit 0
- [ ] `python -m pytest tests/worker/test_pipeline.int.test.py -v` — 3/3 pass (no regressions)
- [ ] Git log shows 6 commits, one per task

## Notes

- Task 3 (SOAR bridge): `run_soar_playbooks` is called via `asyncio.ensure_future` — fire-and-forget, does not block AI triage.
- Task 4 (ThreatHunt): `ThreatHunt` model does not have a `group_id` unique constraint, so the 24h duplicate check is done in application code.
- Task 5 (re-index queue): The `_push_rag_reindex` helper in cases.py opens its own Redis connection rather than reusing a global — this is intentional because server-api and worker are separate processes with separate connection pools.
- Task 6 (report narrative): If `groq_api_key` is empty, `_generate_ai_narrative` returns `""` and the digest sends without a narrative section — graceful degradation.
- The `gte`/`lte` operators added to SOAR in Task 3 let analysts write playbooks like: `field=ai_confidence, operator=gte, value=0.85` to fire only on high-confidence escalations.
