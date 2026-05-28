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


async def _get_fim_events(entity_type: str, entity_value: str) -> str:
    """Fetch FIM events correlated to a host entity in the last 24h."""
    if entity_type != "host":
        return ""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        from sqlalchemy import text
        from worker.models import Agent
        async with AsyncSessionLocal() as db:
            agent_rows = (await db.execute(
                select(Agent.id).where(Agent.hostname == entity_value)
            )).fetchall()
            if not agent_rows:
                return ""
            agent_ids = [str(r[0]) for r in agent_rows]
            fim_rows = (await db.execute(
                text(
                    "SELECT path, event_type, sha256, detected_at "
                    "FROM fim_events "
                    "WHERE agent_id = ANY(:ids) AND detected_at >= :cutoff "
                    "ORDER BY detected_at DESC LIMIT 15"
                ),
                {"ids": agent_ids, "cutoff": cutoff},
            )).fetchall()

        if not fim_rows:
            return ""
        lines = []
        for r in fim_rows:
            ts  = r.detected_at.strftime('%H:%M') if r.detected_at else "?"
            sha = f" sha256={r.sha256[:12]}…" if r.sha256 else ""
            lines.append(f"  [{ts}] {r.event_type} {r.path}{sha}")
        return f"{len(fim_rows)} file integrity event(s) in last 24h:\n" + "\n".join(lines)
    except Exception as exc:
        log.warning("ueba_fim_fetch_failed", error=str(exc))
        return ""


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


_PRIVATE_NETS = (
    "10.", "192.168.", "127.", "0.0.0.0", "::1", "fe80::",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_NETS)


def _extract_ips_from_events(events: list, exclude: set[str]) -> list[str]:
    """Extract public IPs from event decoded_fields, excluding already-known IPs."""
    import json as _json
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    seen: set[str] = set(exclude)
    results: list[str] = []
    for ev in events:
        df = ev.decoded_fields or {}
        try:
            text = _json.dumps(df)
        except Exception:
            continue
        for ioc in extract_iocs(text):
            if ioc.type not in (IOCType.ipv4, IOCType.ipv6):
                continue
            ip = ioc.value
            if _is_private_ip(ip) or ip in seen:
                continue
            seen.add(ip)
            results.append(ip)
    return results[:8]


async def _run_ti_ips(redis, ips: list[str]) -> list[dict]:
    """Lookup TI for IPs from logs. Reuses ti:cache:{ip} shared with _run_ti()."""
    if not ips:
        return []

    cfg = await _build_ti_config()
    from worker.ti.providers.abuseipdb import AbuseIPDBProvider
    from worker.ti.providers.virustotal import VirusTotalProvider
    from worker.ti.providers.otx import OTXProvider
    from worker.ti.providers.greynoise import GreyNoiseProvider

    abuse_p = AbuseIPDBProvider(cfg)
    vt_p    = VirusTotalProvider(cfg)
    otx_p   = OTXProvider(cfg)
    gn_p    = GreyNoiseProvider(cfg)

    results: list[dict] = []

    for ip in ips:
        cache_key = f"ti:cache:{ip}"
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            results.append({"ip": ip, "score": data.get("score", 0.0), "bullets": data.get("bullets", []), "cached_at": data.get("cached_at", "")})
            continue

        try:
            abuse, vt, otx, gn = await asyncio.gather(
                abuse_p.lookup_ip(ip),
                vt_p.lookup_ip(ip),
                otx_p.lookup_ip(ip),
                gn_p.lookup_ip(ip),
            )

            bullets: list[str] = []
            risk = 0.0

            if not abuse.get("skipped"):
                ac = abuse.get("data", {}).get("abuseConfidenceScore")
                if ac is not None:
                    bullets.append(f"abuseipdb: abuseConfidenceScore={ac}")
                    risk = max(risk, min(1.0, float(ac) / 100.0))

            stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if not vt.get("skipped") and not vt.get("not_found"):
                mal = int(stats.get("malicious") or 0)
                sus = int(stats.get("suspicious") or 0)
                bullets.append(f"virustotal(ip): malicious={mal} suspicious={sus}")
                tot = sum(int(stats.get(k) or 0) for k in ("harmless", "malicious", "suspicious"))
                if tot and mal:
                    risk = max(risk, min(1.0, mal / tot + 0.1))

            pc = otx.get("pulse_info", {}).get("count")
            if not otx.get("skipped") and not otx.get("not_found") and pc is not None:
                bullets.append(f"otx(ip): pulse_count={pc}")
                if isinstance(pc, int) and pc > 0:
                    risk = max(risk, min(1.0, 0.2 + min(pc, 10) / 50.0))

            if not gn.get("skipped") and not gn.get("not_found"):
                bits: list[str] = []
                if "noise" in gn:
                    bits.append(f"noise={gn['noise']}")
                if cls := (gn.get("classification") or gn.get("grey_type")):
                    bits.append(f"class={str(cls)[:60]}")
                if bits:
                    bullets.append(f"greynoise: {' '.join(bits)}")
                if str(gn.get("classification") or "").lower().find("malicious") >= 0:
                    risk = max(risk, 0.82)
                elif isinstance(gn.get("noise"), bool) and gn["noise"]:
                    risk = max(risk, 0.35)

            entry = {
                "score":     round(risk, 3),
                "sources":   [],
                "bullets":   bullets,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            await redis.setex(cache_key, TI_CACHE_TTL, json.dumps(entry))

            results.append({"ip": ip, "score": entry["score"], "bullets": bullets, "cached_at": entry["cached_at"]})
        except Exception as exc:
            log.warning("ueba_ip_ti_failed", ip=ip, error=str(exc))

    return results


def _format_ip_ti(hits: list[dict]) -> str:
    if not hits:
        return "No additional public IPs detected in recent logs."
    lines = []
    for h in hits:
        score = h.get("score", 0.0)
        lines.append(f"  {h['ip']}  score={score:.2f}")
        for b in h.get("bullets", []):
            lines.append(f"    {b}")
    return "\n".join(lines)


import re as _re
import base64 as _base64

_PS_PATTERNS: list[tuple[str, str, float]] = [
    (r'-[Ee]nc(?:odedCommand)?\b',                        'base64_encoded',        0.40),
    (r'(?i)\biex\b|invoke-expression',                    'invoke_expression',     0.35),
    (r'(?i)downloadstring|new-object\s+net\.webclient',   'download_cradle',       0.55),
    (r'(?i)executionpolicy\s+bypass|bypass',              'policy_bypass',         0.30),
    (r'(?i)-nop(?:rofile)?\b',                            'noprofile',             0.10),
    (r'(?i)-[Ww]\s*hid(?:den)?\b',                        'hidden_window',         0.25),
    (r'(?i)amsiutils|amsi\.dll|amsi_bypass',              'amsi_bypass',           0.70),
    (r'(?i)mimikatz|sekurlsa|lsadump|invoke-mimikatz',    'credential_dump',       0.95),
    (r'(?i)invoke-shellcode|reflectivepe|invoke-empire',  'exploit_framework',     0.90),
    (r'(?i)\[convert\]::frombase64string',                'runtime_b64_decode',    0.35),
    (r'(?i)shellcode|meterpreter|cobalt.{0,4}strike',     'c2_framework',          0.95),
    (r'(?i)reg\s+add.*\\run\b|new-itemproperty.*\\run\b', 'persistence_registry',  0.75),
    (r'(?i)certutil.*-urlcache|-decode',                  'certutil_abuse',        0.65),
    (r'(?i)bitsadmin\s+/transfer',                        'bitsadmin_abuse',       0.60),
    (r'(?i)net\s+user\s+\S+\s+\S+\s*/add',               'user_add',              0.75),
    (r'(?i)net\s+localgroup.*administrators.*\/add',      'admin_group_add',       0.80),
    (r'(?i)sc\s+(create|config)\s+.*binpath',             'service_install',       0.70),
    (r'(?i)schtasks.*\/create',                           'scheduled_task',        0.65),
    (r'(?i)wmic\s+(process|product)\s+(call|get)',        'wmi_exec',              0.55),
]

_B64_CMD_RE = _re.compile(
    r'-[Ee](?:nc(?:odedCommand)?)?\s+([A-Za-z0-9+/=]{20,})', _re.IGNORECASE
)


def _decode_ps_b64(command: str) -> str | None:
    m = _B64_CMD_RE.search(command)
    if not m:
        return None
    raw = m.group(1)
    # PowerShell encodes in UTF-16LE
    for pad in ('', '=', '=='):
        try:
            decoded = _base64.b64decode(raw + pad).decode('utf-16-le', errors='replace')
            if decoded.isprintable() or len(decoded) > 10:
                return decoded[:2000]
        except Exception:
            pass
    return None


def _extract_powershell_from_events(events: list) -> list[str]:
    """Extract PowerShell command strings from event decoded_fields."""
    import json as _json
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    seen: set[str] = set()
    results: list[str] = []
    for ev in events:
        df = ev.decoded_fields or {}
        try:
            text = _json.dumps(df)
        except Exception:
            continue
        for ioc in extract_iocs(text):
            if ioc.type in (IOCType.powershell, IOCType.command):
                cmd = ioc.value.strip()
                key = cmd[:120]
                if key not in seen:
                    seen.add(key)
                    results.append(cmd)
    return results[:5]


def _analyze_powershell(commands: list[str]) -> list[dict]:
    """Heuristic analysis of PowerShell commands — no external API calls."""
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    results: list[dict] = []
    for cmd in commands:
        flags: list[str] = []
        score = 0.0

        for pattern, flag, weight in _PS_PATTERNS:
            if _re.search(pattern, cmd):
                flags.append(flag)
                score = min(1.0, score + weight)

        decoded = _decode_ps_b64(cmd)
        analysis_text = (decoded or cmd)

        # Extract secondary IOCs from (decoded) command text
        secondary: list[str] = []
        for ioc in extract_iocs(analysis_text):
            if ioc.type in (IOCType.ipv4, IOCType.ipv6, IOCType.domain, IOCType.url):
                if not _is_private_ip(ioc.value):
                    secondary.append(f"{ioc.type.value}:{ioc.value}")
        secondary = secondary[:10]

        results.append({
            "command":        cmd[:300],
            "decoded":        decoded[:500] if decoded else None,
            "score":          round(min(score, 1.0), 3),
            "flags":          flags,
            "secondary_iocs": secondary,
        })

    return results


def _format_powershell_analysis(hits: list[dict]) -> str:
    if not hits:
        return "No PowerShell commands detected in recent logs."
    lines = []
    for h in hits:
        lines.append(f"  CMD: {h['command'][:120]}{'…' if len(h['command']) > 120 else ''}")
        lines.append(f"  Score: {h['score']:.2f}  Flags: {', '.join(h['flags']) or 'none'}")
        if h.get("decoded"):
            lines.append(f"  Decoded: {h['decoded'][:200]}{'…' if len(h['decoded']) > 200 else ''}")
        if h.get("secondary_iocs"):
            lines.append(f"  IOCs in command: {', '.join(h['secondary_iocs'])}")
        lines.append("")
    return "\n".join(lines).rstrip()


_CMD_PATTERNS: list[tuple[str, str, float]] = [
    # download/fetch
    (r'(?i)curl\s+.*-[oO]\s+\S+|curl\s+.*http',           'curl_download',         0.40),
    (r'(?i)wget\s+.*-[oO]\s+\S+|wget\s+.*http',           'wget_download',         0.40),
    (r'(?i)certutil\s+.*-urlcache\s+-[Ss]plit',           'certutil_download',     0.65),
    (r'(?i)certutil\s+.*-decode',                          'certutil_decode',       0.55),
    (r'(?i)bitsadmin\s+/transfer',                         'bitsadmin_download',    0.60),
    # execution / LOLBins
    (r'(?i)rundll32\s+\S+,\S+',                            'rundll32_exec',         0.65),
    (r'(?i)regsvr32\s+.*/[Ss]\s',                          'regsvr32_scrobj',       0.70),
    (r'(?i)mshta\s+http',                                  'mshta_remote',          0.75),
    (r'(?i)wscript\s+\S+\.(js|vbs|wsf)',                   'wscript_script',        0.60),
    (r'(?i)cscript\s+\S+\.(js|vbs|wsf)',                   'cscript_script',        0.60),
    (r'(?i)msiexec\s+.*/[qQ]\s.*/[iI]\s+http',            'msiexec_remote',        0.70),
    # shell chaining
    (r'\|\s*(?:bash|sh|zsh|cmd)\b',                        'pipe_to_shell',         0.55),
    (r'(?i)base64\s+-d\s*\|',                              'b64_pipe_shell',        0.65),
    (r'&&\s*(?:curl|wget|bash|sh|python|perl|ruby)\b',     'chain_exec',            0.45),
    # recon
    (r'(?i)\bwhoami\b',                                    'recon_whoami',          0.20),
    (r'(?i)\bnet\s+user\b|\bnet\s+group\b',                'recon_net_enum',        0.25),
    (r'(?i)\barp\s+-a\b|\bnetstat\b|\bipconfig\b|\bifconfig\b', 'recon_network',    0.20),
    # privilege / lateral movement
    (r'(?i)net\s+user\s+\S+\s+\S+\s*/add',                'user_add',              0.80),
    (r'(?i)net\s+localgroup.*administrators.*\/add',        'admin_group_add',       0.85),
    (r'(?i)ssh\s+.*-[Rr]\s+\d+:',                         'ssh_tunnel',            0.65),
    (r'(?i)nc\s+.*-[eElLp]|ncat\s+.*-[eE]',               'netcat_shell',          0.80),
    # persistence
    (r'(?i)schtasks\s+/create',                            'scheduled_task',        0.65),
    (r'(?i)sc\s+(create|config)\s+.*binpath',              'service_install',       0.70),
    (r'(?i)reg\s+add.*\\run\b',                            'registry_run_key',      0.75),
    (r'(?i)crontab\s+-[el]',                               'crontab_edit',          0.50),
    (r'(?i)at\s+\d{1,2}:\d{2}\s+',                        'at_scheduler',          0.55),
    # defence evasion
    (r'(?i)auditpol\s+/set.*failure:disable',              'audit_disable',         0.75),
    (r'(?i)wevtutil\s+cl\s',                               'eventlog_clear',        0.85),
    (r'(?i)setenforce\s+0|selinux.*permissive',            'selinux_disable',       0.70),
    (r'(?i)ufw\s+disable|iptables\s+-[FXZ]',              'firewall_disable',      0.75),
    (r'(?i)chmod\s+[4-7][0-7][0-7][0-7]\s+',              'suid_setuid',           0.60),
]


def _extract_commands_from_events(events: list) -> list[str]:
    """Extract non-PowerShell suspicious command strings from event decoded_fields."""
    import json as _json
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    seen: set[str] = set()
    results: list[str] = []
    for ev in events:
        df = ev.decoded_fields or {}
        try:
            text = _json.dumps(df)
        except Exception:
            continue
        for ioc in extract_iocs(text):
            if ioc.type != IOCType.command:
                continue
            cmd = ioc.value.strip()
            key = cmd[:120]
            if key not in seen:
                seen.add(key)
                results.append(cmd)
    return results[:8]


def _analyze_commands(commands: list[str]) -> list[dict]:
    """Heuristic analysis of non-PowerShell suspicious commands."""
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    results: list[dict] = []
    for cmd in commands:
        flags: list[str] = []
        score = 0.0

        for pattern, flag, weight in _CMD_PATTERNS:
            if _re.search(pattern, cmd):
                flags.append(flag)
                score = min(1.0, score + weight)

        secondary: list[str] = []
        for ioc in extract_iocs(cmd):
            if ioc.type in (IOCType.ipv4, IOCType.ipv6, IOCType.domain, IOCType.url):
                if not _is_private_ip(ioc.value):
                    secondary.append(f"{ioc.type.value}:{ioc.value}")
        secondary = secondary[:10]

        if flags:  # only include commands that matched at least one pattern
            results.append({
                "command":        cmd[:400],
                "score":          round(min(score, 1.0), 3),
                "flags":          flags,
                "secondary_iocs": secondary,
            })

    return results


def _format_command_analysis(hits: list[dict]) -> str:
    if not hits:
        return "No suspicious non-PowerShell commands detected in recent logs."
    lines = []
    for h in hits:
        lines.append(f"  CMD: {h['command'][:120]}{'…' if len(h['command']) > 120 else ''}")
        lines.append(f"  Score: {h['score']:.2f}  Flags: {', '.join(h['flags'])}")
        if h.get("secondary_iocs"):
            lines.append(f"  IOCs: {', '.join(h['secondary_iocs'])}")
        lines.append("")
    return "\n".join(lines).rstrip()


_INTERNAL_DOMAIN_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home", ".localdomain")
_SKIP_DOMAINS = {"localhost", "broadcasthost"}


def _extract_domains_from_events(events: list) -> list[str]:
    """Extract external domains from event decoded_fields. Returns list of domain strings."""
    import json as _json
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    seen: set[str] = set()
    results: list[str] = []
    for ev in events:
        df = ev.decoded_fields or {}
        try:
            text = _json.dumps(df)
        except Exception:
            continue
        for ioc in extract_iocs(text):
            if ioc.type != IOCType.domain:
                continue
            dom = ioc.value.lower()
            if dom in _SKIP_DOMAINS:
                continue
            if any(dom.endswith(s) for s in _INTERNAL_DOMAIN_SUFFIXES):
                continue
            if dom not in seen:
                seen.add(dom)
                results.append(dom)
    return results[:8]


async def _run_ti_domains(redis, domains: list[str]) -> list[dict]:
    """Lookup TI for domains. Checks ti:cache:domain:{d} first, caches misses for 24h."""
    if not domains:
        return []

    cfg = await _build_ti_config()
    from worker.ti.providers.virustotal import VirusTotalProvider
    from worker.ti.providers.otx import OTXProvider
    from worker.ti.providers.urlhaus import URLhausProvider

    vt_p  = VirusTotalProvider(cfg)
    otx_p = OTXProvider(cfg)
    uh_p  = URLhausProvider(cfg)

    results: list[dict] = []

    for dom in domains:
        cache_key = f"ti:cache:domain:{dom}"
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            results.append({"domain": dom, **data})
            continue

        try:
            vt, otx, uh = await asyncio.gather(
                vt_p.lookup_domain(dom),
                otx_p.lookup_domain(dom),
                uh_p.lookup_domain(dom),
            )

            bullets: list[str] = []
            risk = 0.0

            stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if not vt.get("skipped") and not vt.get("not_found"):
                mal = int(stats.get("malicious") or 0)
                sus = int(stats.get("suspicious") or 0)
                bullets.append(f"virustotal(domain): malicious={mal} suspicious={sus}")
                tot = sum(int(stats.get(k) or 0) for k in ("harmless", "malicious", "suspicious", "undetected"))
                if tot and mal:
                    risk = max(risk, min(1.0, 0.5 + mal / 40.0))

            pc = otx.get("pulse_info", {}).get("count")
            if not otx.get("skipped") and not otx.get("not_found") and pc is not None:
                bullets.append(f"otx(domain): pulse_count={pc}")
                if isinstance(pc, int) and pc > 0:
                    risk = max(risk, min(1.0, 0.2 + min(pc, 10) / 50.0))

            if not uh.get("skipped") and uh.get("query_status") == "ok":
                if ref := uh.get("urlhaus_reference"):
                    bullets.append(f"urlhaus(domain): listed ref={ref}")
                    risk = max(risk, 0.65)

            entry = {
                "score":     round(risk, 3),
                "bullets":   bullets,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            await redis.setex(cache_key, TI_HASH_CACHE_TTL, json.dumps(entry))

            results.append({"domain": dom, **entry})
        except Exception as exc:
            log.warning("ueba_domain_ti_failed", domain=dom, error=str(exc))

    return results


def _format_domain_ti(hits: list[dict]) -> str:
    if not hits:
        return "No external domains detected in recent logs."
    lines = []
    for h in hits:
        score = h.get("score", 0.0)
        bullets = h.get("bullets", [])
        lines.append(f"  {h['domain']}  score={score:.2f}")
        for b in bullets:
            lines.append(f"    {b}")
    return "\n".join(lines)


_INTERNAL_URL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_INTERNAL_URL_PREFIXES = ("http://10.", "http://192.168.", "http://172.16.", "http://172.17.",
                          "https://10.", "https://192.168.", "https://172.16.", "https://172.17.")


def _extract_urls_from_events(events: list) -> list[str]:
    """Extract external HTTP(S) URLs from event decoded_fields."""
    import json as _json
    from urllib.parse import urlparse
    from worker.ti.extractor import extract_iocs
    from worker.ti.iocs import IOCType

    seen: set[str] = set()
    results: list[str] = []
    for ev in events:
        df = ev.decoded_fields or {}
        try:
            text = _json.dumps(df)
        except Exception:
            continue
        for ioc in extract_iocs(text):
            if ioc.type != IOCType.url:
                continue
            url = ioc.value
            if any(url.startswith(p) for p in _INTERNAL_URL_PREFIXES):
                continue
            try:
                host = urlparse(url).hostname or ""
                if host in _INTERNAL_URL_HOSTS:
                    continue
            except Exception:
                continue
            if url not in seen:
                seen.add(url)
                results.append(url)
    return results[:8]


async def _run_ti_urls(redis, urls: list[str]) -> list[dict]:
    """Lookup TI for URLs. Checks ti:cache:url:{md5} first, caches misses for 24h."""
    if not urls:
        return []

    import hashlib

    cfg = await _build_ti_config()
    from worker.ti.providers.virustotal import VirusTotalProvider
    from worker.ti.providers.otx import OTXProvider
    from worker.ti.providers.urlhaus import URLhausProvider

    vt_p  = VirusTotalProvider(cfg)
    otx_p = OTXProvider(cfg)
    uh_p  = URLhausProvider(cfg)

    results: list[dict] = []

    for url in urls:
        url_key = hashlib.md5(url.encode()).hexdigest()
        cache_key = f"ti:cache:url:{url_key}"
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            results.append({"url": url, **data})
            continue

        try:
            uh, vt, otx = await asyncio.gather(
                uh_p.lookup_url(url),
                vt_p.lookup_url(url),
                otx_p.lookup_url(url),
            )

            bullets: list[str] = []
            risk = 0.0

            if not uh.get("skipped"):
                qs = uh.get("query_status", "")
                if qs == "ok":
                    parts: list[str] = []
                    if ref := uh.get("urlhaus_reference"):
                        parts.append(f"ref={ref}")
                    if st := uh.get("urlhaus_status"):
                        parts.append(f"status={st}")
                    if parts:
                        bullets.append(f"urlhaus(url): {', '.join(parts)}")
                        risk = max(risk, 0.85)

            stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if not vt.get("skipped") and not vt.get("not_found"):
                mal = int(stats.get("malicious") or 0)
                sus = int(stats.get("suspicious") or 0)
                bullets.append(f"virustotal(url): malicious={mal} suspicious={sus}")
                tot = sum(int(stats.get(k) or 0) for k in ("harmless", "malicious", "suspicious", "undetected"))
                if tot and mal:
                    risk = max(risk, min(1.0, 0.5 + mal / 40.0))

            pc = otx.get("pulse_info", {}).get("count")
            if not otx.get("skipped") and not otx.get("not_found") and pc is not None:
                bullets.append(f"otx(url): pulse_count={pc}")
                if isinstance(pc, int) and pc > 0:
                    risk = max(risk, min(1.0, 0.2 + min(pc, 10) / 50.0))

            entry = {
                "score":     round(risk, 3),
                "bullets":   bullets,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            await redis.setex(cache_key, TI_HASH_CACHE_TTL, json.dumps(entry))

            results.append({"url": url, **entry})
        except Exception as exc:
            log.warning("ueba_url_ti_failed", url=url[:60], error=str(exc))

    return results


def _format_url_ti(hits: list[dict]) -> str:
    if not hits:
        return "No external URLs detected in recent logs."
    lines = []
    for h in hits:
        score = h.get("score", 0.0)
        short_url = h["url"][:80] + ("…" if len(h["url"]) > 80 else "")
        lines.append(f"  {short_url}  score={score:.2f}")
        for b in h.get("bullets", []):
            lines.append(f"    {b}")
    return "\n".join(lines)


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
    domain_ti_hits: list[dict] | None = None,
    url_ti_hits: list[dict] | None = None,
    ip_ti_hits: list[dict] | None = None,
    powershell_hits: list[dict] | None = None,
    command_hits: list[dict] | None = None,
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
            ioc_data={"mitre_techniques": mitre_techniques, "hash_ti_hits": hash_ti_hits or [], "domain_ti_hits": domain_ti_hits or [], "url_ti_hits": url_ti_hits or [], "ip_ti_hits": ip_ti_hits or [], "powershell_hits": powershell_hits or [], "command_hits": command_hits or []},
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
    domain_ti_hits: list[dict],
    url_ti_hits: list[dict],
    ip_ti_hits: list[dict],
    powershell_hits: list[dict],
    command_hits: list[dict],
) -> None:
    try:
        async with AsyncSessionLocal() as db:
            row = await db.get(UebaAnomaly, uuid.UUID(anomaly_id))
            if row:
                row.mitre_techniques = mitre_techniques
                row.ai_narrative     = ai_narrative
                row.ai_action        = ai_action.lower()
                row.hash_ti_hits     = hash_ti_hits
                row.domain_ti_hits   = domain_ti_hits
                row.url_ti_hits      = url_ti_hits
                row.ip_ti_hits       = ip_ti_hits
                row.powershell_hits  = powershell_hits
                row.command_hits     = command_hits
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

    # 3. Recent logs + IOC extraction
    logs_text, recent_events = await _get_recent_logs(entity_type, entity_value)
    hash_iocs   = _extract_hashes_from_events(recent_events)
    domain_iocs = _extract_domains_from_events(recent_events)
    url_iocs    = _extract_urls_from_events(recent_events)
    _known_ips  = {ip for ip in (source_ip, entity_value if entity_type == "ip" else None) if ip}
    ip_iocs     = _extract_ips_from_events(recent_events, exclude=_known_ips)
    ps_commands     = _extract_powershell_from_events(recent_events)
    shell_commands  = _extract_commands_from_events(recent_events)
    powershell_hits = _analyze_powershell(ps_commands)    # sync — no I/O
    command_hits    = _analyze_commands(shell_commands)   # sync — no I/O
    hash_ti_hits, domain_ti_hits, url_ti_hits, ip_ti_hits = await asyncio.gather(
        _run_ti_hashes(redis, hash_iocs),
        _run_ti_domains(redis, domain_iocs),
        _run_ti_urls(redis, url_iocs),
        _run_ti_ips(redis, ip_iocs),
    )

    # 4. Case memory + broader context (parallel)
    similar_cases, alert_history_text, concurrent_text, fim_text = await asyncio.gather(
        _get_similar_cases(entity_type, mitre_ids),
        _get_entity_alert_history(source_ip, hostname),
        _get_concurrent_anomalies(entity_type, entity_value),
        _get_fim_events(entity_type, entity_value),
    )

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

DOMAIN INTELLIGENCE ({len(domain_ti_hits)} external domain(s) found in logs):
{_format_domain_ti(domain_ti_hits)}

URL INTELLIGENCE ({len(url_ti_hits)} external URL(s) found in logs):
{_format_url_ti(url_ti_hits)}

RELATED IP INTELLIGENCE ({len(ip_ti_hits)} additional public IP(s) found in logs):
{_format_ip_ti(ip_ti_hits)}

POWERSHELL ANALYSIS ({len(powershell_hits)} command(s) detected):
{_format_powershell_analysis(powershell_hits)}

SUSPICIOUS COMMAND ANALYSIS ({len(command_hits)} command(s) detected):
{_format_command_analysis(command_hits)}
{f"FILE INTEGRITY MONITORING:{chr(10)}{fim_text}" if fim_text else ""}
Analyze all evidence. Consider whether this is an isolated event or part of a broader attack pattern, and reflect that in your narrative and confidence. Provide your investigation verdict as JSON."""

    # Truncate prompt if too long to avoid Groq context overflow
    _MAX_PROMPT = 14_000
    if len(prompt) > _MAX_PROMPT:
        prompt = prompt[:_MAX_PROMPT] + "\n\n[Context truncated — respond based on available evidence above.]"

    # 7. Groq analysis
    ai_response = await _call_groq(prompt)
    action = ai_response.get("action", "ALERT").upper()

    # Write ML feedback scores to Redis for next snapshot cycle
    _score_ttl = 7 * 86400
    _et, _ev = entity_type, entity_value

    all_ti_scores = (
        [h["score"] for h in hash_ti_hits]
        + [h["score"] for h in domain_ti_hits]
        + [h["score"] for h in url_ti_hits]
        + [h["score"] for h in ip_ti_hits]
    )
    max_ps_score  = max((h["score"] for h in powershell_hits), default=0.0)
    max_cmd_score = max((h["score"] for h in command_hits),    default=0.0)

    writes = []
    if all_ti_scores and (s := max(all_ti_scores)) > 0:
        writes.append(redis.set(f"ueba:ioc_score:{_et}:{_ev}", str(s),  ex=_score_ttl))
    if max_ps_score > 0:
        writes.append(redis.set(f"ueba:ps_score:{_et}:{_ev}",  str(max_ps_score),  ex=_score_ttl))
    if max_cmd_score > 0:
        writes.append(redis.set(f"ueba:cmd_score:{_et}:{_ev}", str(max_cmd_score), ex=_score_ttl))
    if writes:
        await asyncio.gather(*writes)

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
            domain_ti_hits=domain_ti_hits,
            url_ti_hits=url_ti_hits,
            ip_ti_hits=ip_ti_hits,
            powershell_hits=powershell_hits,
            command_hits=command_hits,
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
        domain_ti_hits=domain_ti_hits,
        url_ti_hits=url_ti_hits,
        ip_ti_hits=ip_ti_hits,
        powershell_hits=powershell_hits,
        command_hits=command_hits,
    )

    # 10. Persist AI verdict to entity risk score immediately (don't wait for next ML cycle)
    try:
        from worker.models import UebaEntityScore
        async with AsyncSessionLocal() as db:
            row = await db.get(UebaEntityScore, (entity_type, entity_value))
            if row:
                now_ts = datetime.now(timezone.utc)
                if action == "ESCALATE":
                    row.risk_score      = max(row.risk_score, risk_score)
                    row.last_anomaly_at = now_ts
                elif action == "DISMISS":
                    row.risk_score = row.risk_score * 0.5  # aggressive decay — AI cleared it
                row.updated_at = now_ts
                await db.commit()
    except Exception as exc:
        log.warning("ueba_risk_persist_failed", entity_type=entity_type,
                    entity_value=entity_value, error=str(exc))


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
