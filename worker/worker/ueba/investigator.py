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
from worker.models import UebaAnomaly, Case, CaseNote
from worker.settings_cache import get_setting
from worker.ueba.mitre_mapper import map_to_mitre

log = structlog.get_logger()

UEBA_INVESTIGATE_QUEUE = "siem:ueba:investigate"
TI_CACHE_TTL      = 86400  # 24 hours (IP)
TI_HASH_CACHE_TTL = 86400  # 24 hours (hash)


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
    """Map TI overall_risk (0-1) to a discrete reputation score for the ML cache."""
    if overall_risk >= 0.8:
        return 1.0
    if overall_risk >= 0.5:
        return 0.8
    if overall_risk >= 0.2:
        return 0.5
    return 0.0


async def _run_ti(redis, source_ip: str | None) -> tuple[str, float]:
    """Run TI enrichment on source_ip, cache result, return (bullets_text, ti_score)."""
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


async def _get_recent_logs(entity_type: str, entity_value: str) -> tuple[str, list]:
    """Fetch last 20 events for this entity. Returns (formatted_text, raw_event_list)."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    try:
        from worker.models import Event as Ev
        async with AsyncSessionLocal() as db:
            if entity_type == "ip":
                q = select(Ev).where(Ev.source_ip == entity_value).where(Ev.created_at >= cutoff)
            elif entity_type == "user":
                q = select(Ev).where(Ev.user_name == entity_value).where(Ev.created_at >= cutoff)
            else:
                from sqlalchemy import cast, Text
                q = select(Ev).where(
                    cast(Ev.decoded_fields, Text).contains(entity_value)
                ).where(Ev.created_at >= cutoff)

            rows = (await db.execute(q.order_by(Ev.created_at.desc()).limit(20))).scalars().all()

        if not rows:
            return "No recent log entries found.", []
        lines = []
        for r in rows:
            ts = r.created_at.strftime('%H:%M:%S') if r.created_at else "?"
            df = r.decoded_fields or {}
            summary = df.get("event.action") or df.get("event_action") or r.event_action or r.event_category or "event"
            src = f" src={r.source_ip}" if r.source_ip else ""
            user = f" user={r.user_name}" if r.user_name else ""
            lines.append(f"[{ts}] {summary}{src}{user}")
        return "\n".join(lines), list(rows)
    except Exception as exc:
        log.warning("ueba_log_fetch_failed", error=str(exc))
        return "Log fetch failed.", []


def _extract_hashes_from_events(events: list) -> list[tuple[str, str]]:
    """Extract file hashes from event decoded_fields. Returns [(hash_value, ioc_type)]."""
    import json as _json
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    seen: set[str] = set()
    results: list[tuple[str, str]] = []
    for ev in events:
        df = ev.decoded_fields or {}
        try:
            text = _json.dumps(df)
        except Exception:
            continue
        for ioc in extract_iocs(text):
            if ioc.type in (IOCType.hash_md5, IOCType.hash_sha1, IOCType.hash_sha256):
                if ioc.value not in seen:
                    seen.add(ioc.value)
                    results.append((ioc.value, ioc.type.value))
    return results[:10]


async def _run_ti_hashes(redis, hashes: list[tuple[str, str]]) -> list[dict]:
    """Lookup TI for file hashes. Checks ti:cache:hash:{h} first, caches misses for 24h."""
    if not hashes:
        return []

    cfg = await _build_ti_config()
    from worker.ti.providers.virustotal import VirusTotalProvider
    from worker.ti.providers.otx import OTXProvider
    from worker.ti.providers.urlhaus import URLhausProvider

    vt_p  = VirusTotalProvider(cfg)
    otx_p = OTXProvider(cfg)
    uh_p  = URLhausProvider(cfg)

    results: list[dict] = []

    for h, ioc_type in hashes:
        cache_key = f"ti:cache:hash:{h}"
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            results.append({"hash": h, "ioc_type": ioc_type, **data})
            continue

        try:
            vt, otx, uh = await asyncio.gather(
                vt_p.lookup_hash(h),
                otx_p.lookup_hash(h),
                uh_p.lookup_hash(h),
            )

            bullets: list[str] = []
            risk = 0.0

            stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if not vt.get("skipped") and not vt.get("not_found"):
                mal = int(stats.get("malicious") or 0)
                sus = int(stats.get("suspicious") or 0)
                bullets.append(f"virustotal(hash): malicious={mal} suspicious={sus}")
                tot = sum(int(stats.get(k) or 0) for k in ("harmless", "malicious", "suspicious", "undetected"))
                if tot and mal:
                    risk = max(risk, min(1.0, 0.5 + mal / 40.0))

            pc = otx.get("pulse_info", {}).get("count")
            if not otx.get("skipped") and not otx.get("not_found") and pc is not None:
                bullets.append(f"otx(hash): pulse_count={pc}")
                if isinstance(pc, int) and pc > 0:
                    risk = max(risk, min(1.0, 0.2 + min(pc, 10) / 50.0))

            if not uh.get("skipped") and uh.get("query_status") == "ok":
                parts: list[str] = []
                if sig := (uh.get("signature") or uh.get("malware_printable")):
                    parts.append(f"sig={str(sig)[:160]}")
                if st := uh.get("urlhaus_status"):
                    parts.append(f"urlhaus={st}")
                if parts:
                    bullets.append(f"urlhaus(hash): {', '.join(parts)}")
                    risk = max(risk, 0.78)

            entry = {
                "score":     round(risk, 3),
                "bullets":   bullets,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            await redis.setex(cache_key, TI_HASH_CACHE_TTL, json.dumps(entry))

            results.append({"hash": h, "ioc_type": ioc_type, **entry})
        except Exception as exc:
            log.warning("ueba_hash_ti_failed", hash=h[:16], error=str(exc))

    return results


async def _get_entity_alert_history(source_ip: str | None, hostname: str | None) -> str:
    """Fetch last 24h alerts matching this entity's IP or hostname."""
    if not source_ip and not hostname:
        return "No IP or hostname to correlate."
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        from worker.models import Alert
        from sqlalchemy import or_
        async with AsyncSessionLocal() as db:
            conditions = []
            if source_ip:
                conditions.append(Alert.source_ip == source_ip)
            if hostname:
                conditions.append(Alert.hostname == hostname)
            rows = (await db.execute(
                select(Alert)
                .where(or_(*conditions))
                .where(Alert.created_at >= cutoff)
                .order_by(Alert.created_at.desc())
                .limit(20)
            )).scalars().all()

        if not rows:
            return "No alerts found for this entity in the last 24 hours."

        sev_counts: dict[str, int] = {}
        lines = []
        for r in rows:
            sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
            ts = r.created_at.strftime("%H:%M") if r.created_at else "?"
            lines.append(f"  [{ts}] [{r.severity.upper()}] {r.title} (status={r.status})")

        summary = ", ".join(f"{v}x {k}" for k, v in sorted(sev_counts.items()))
        return f"Total: {len(rows)} alerts ({summary})\n" + "\n".join(lines[:10])
    except Exception as exc:
        log.warning("ueba_alert_history_failed", error=str(exc))
        return "Alert history fetch failed."


async def _get_concurrent_anomalies(entity_type: str, entity_value: str) -> str:
    """Find other entities that showed anomalies in the same 24h window (wave detection)."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        from worker.models import UebaEntityScore
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(UebaEntityScore)
                .where(UebaEntityScore.last_anomaly_at >= cutoff)
                .where(
                    (UebaEntityScore.entity_type != entity_type) |
                    (UebaEntityScore.entity_value != entity_value)
                )
                .order_by(UebaEntityScore.risk_score.desc())
                .limit(10)
            )).scalars().all()

        if not rows:
            return "No concurrent anomalies detected — entity appears isolated."

        lines = []
        for r in rows:
            ts = r.last_anomaly_at.strftime("%H:%M") if r.last_anomaly_at else "?"
            lines.append(
                f"  {r.entity_type} \"{r.entity_value}\" | risk={r.risk_score:.0f} | last_anomaly={ts}"
            )
        return f"WARNING: {len(rows)} other entities also anomalous in this 24h window:\n" + "\n".join(lines)
    except Exception as exc:
        log.warning("ueba_concurrent_anomalies_failed", error=str(exc))
        return "Concurrent anomaly fetch failed."


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
                "case_id":   str(r.case_id)[:8],
                "entity":    f'{r.entity_type} "{r.entity_value}"',
                "risk":      f"{r.risk_score:.0f}",
                "mitre":     ", ".join(t["id"] for t in (r.mitre_techniques or [])),
                "action":    r.ai_action or "unknown",
                "narrative": (r.ai_narrative or "")[:300],
                "date":      r.detected_at.strftime("%Y-%m-%d"),
            }
            for _, r in scored[:3]
        ]
    except Exception as exc:
        log.warning("ueba_case_memory_failed", error=str(exc))
        return []


def _format_hash_ti(hits: list[dict]) -> str:
    if not hits:
        return "No file hashes detected in recent logs."
    lines = []
    for h in hits:
        short = h["hash"][:16] + "..."
        ioc_t = h["ioc_type"].replace("hash_", "").upper()
        score = h.get("score", 0.0)
        bullets = h.get("bullets", [])
        lines.append(f"  [{ioc_t}] {short}  score={score:.2f}")
        for b in bullets:
            lines.append(f"    {b}")
    return "\n".join(lines)


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
    enabled = await get_setting("ai_analyst_enabled", "true")
    if enabled.lower() != "true":
        return {"action": "ALERT", "confidence": 0.5,
                "narrative": "AI analyst disabled.", "key_indicators": [], "recommended_action": "Review manually."}

    api_key = await get_setting("groq_api_key")
    if not api_key:
        return {"action": "ALERT", "confidence": 0.5,
                "narrative": "Groq API key not configured.", "key_indicators": [], "recommended_action": "Configure groq_api_key in Settings."}

    model = await get_setting("groq_model", "llama-3.3-70b-versatile")
    system = (
        "You are a senior SIEM security analyst specialising in UEBA (User and Entity Behaviour Analytics). "
        "Investigate the anomaly below and respond ONLY with valid JSON:\n"
        '{"action":"DISMISS"|"ALERT"|"ESCALATE","confidence":0.0-1.0,'
        '"narrative":"2-4 sentence summary","key_indicators":["list"],'
        '"recommended_action":"one specific next step"}'
    )

    from groq import AsyncGroq
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
    hash_ti_hits: list[dict] | None = None,
) -> uuid.UUID:
    async with AsyncSessionLocal() as db:
        case = Case(
            title=f"[UEBA] {entity_type.capitalize()} threat: {entity_value}",
            description=ai_response.get("narrative", ""),
            severity=severity,
            status="open",
            alert_id=alert_id,
            ai_reasoning=json.dumps({
                "key_indicators":     ai_response.get("key_indicators", []),
                "recommended_action": ai_response.get("recommended_action", ""),
                "similar_cases":      [c["case_id"] for c in similar_cases],
                "mitre_techniques":   [t["id"] for t in mitre_techniques],
                "confidence":         ai_response.get("confidence", 0),
            }, ensure_ascii=False),
            ioc_data={"mitre_techniques": mitre_techniques, "hash_ti_hits": hash_ti_hits or []},
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
    hash_ti_hits: list[dict],
) -> None:
    try:
        async with AsyncSessionLocal() as db:
            row = await db.get(UebaAnomaly, uuid.UUID(anomaly_id))
            if row:
                row.mitre_techniques = mitre_techniques
                row.ai_narrative     = ai_narrative
                row.ai_action        = ai_action.lower()
                row.hash_ti_hits     = hash_ti_hits
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

    # 3. Recent logs + hash extraction
    logs_text, recent_events = await _get_recent_logs(entity_type, entity_value)
    hash_iocs    = _extract_hashes_from_events(recent_events)
    hash_ti_hits = await _run_ti_hashes(redis, hash_iocs)

    # 4. Case memory
    similar_cases = await _get_similar_cases(entity_type, mitre_ids)

    # 4b. Broader context — alert history + concurrent wave detection
    alert_history_text = await _get_entity_alert_history(source_ip, hostname)
    concurrent_text    = await _get_concurrent_anomalies(entity_type, entity_value)

    # 5. Entity profile for Z-score context in prompt
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

ENTITY ALERT HISTORY (last 24h):
{alert_history_text}

CONCURRENT ANOMALIES (same 24h window — potential coordinated attack):
{concurrent_text}

FILE HASH INTELLIGENCE ({len(hash_ti_hits)} hash(es) found in logs):
{_format_hash_ti(hash_ti_hits)}

Analyze all evidence. Consider whether this is an isolated event or part of a broader attack pattern, and reflect that in your narrative and confidence. Provide your investigation verdict as JSON."""

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
        await create_alert(
            rule_match={
                "id":    f"ueba-ai-{entity_type}",
                "title": f"[UEBA AI] {entity_type.capitalize()} threat confirmed: {entity_value} [risk: {risk_score:.0f}/100]",
                "level": severity,
                "tags":  ["ueba", "ueba.ai", f"ueba.{entity_type}"] + [t["id"] for t in mitre_techniques],
                "matched_fields": features,
            },
            event_id=None, agent_id=None,
            group_id=group_id,
            source_ip=source_ip,
            hostname=hostname,
        )

    if action == "ESCALATE":
        case_id = await _create_case(
            entity_type=entity_type, entity_value=entity_value,
            risk_score=risk_score, severity=severity,
            alert_id=None,
            ai_response=ai_response, mitre_techniques=mitre_techniques,
            similar_cases=similar_cases, group_id=group_id,
            hash_ti_hits=hash_ti_hits,
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
        hash_ti_hits=hash_ti_hits,
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
