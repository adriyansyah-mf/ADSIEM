# worker/worker/groq_client.py
import asyncio
import json
import os as _os
import httpx
import structlog
from worker.config import GROQ_API_KEY
from worker.settings_cache import get_setting

ANTHROPIC_API_KEY = _os.environ.get("ANTHROPIC_API_KEY", "")

log = structlog.get_logger()
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Max 3 concurrent Groq calls — hindari burst yang memicu rate limit
_groq_semaphore = asyncio.Semaphore(3)


async def _groq_post(api_key: str, payload: dict, max_retries: int = 4) -> dict:
    """POST ke Groq dengan retry exponential backoff saat kena 429."""
    delay = 5.0
    async with _groq_semaphore:
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=40) as client:
                    resp = await client.post(
                        GROQ_API_URL,
                        headers={"Authorization": f"Bearer {api_key}",
                                 "Content-Type": "application/json"},
                        json=payload,
                    )
                    if resp.status_code == 429:
                        retry_after = float(resp.headers.get("retry-after", delay))
                        wait = max(retry_after, delay)
                        log.warning("groq_rate_limited", attempt=attempt + 1,
                                    wait_seconds=wait)
                        await asyncio.sleep(wait)
                        delay = min(delay * 2, 60)
                        continue
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPStatusError:
                raise
            except Exception as exc:
                if attempt == max_retries - 1:
                    raise
                log.warning("groq_retry", attempt=attempt + 1, error=str(exc))
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)
    raise RuntimeError("Groq max retries exceeded")

_L1_SYSTEM_PROMPT = """You are an on-duty L1 SOC Analyst. You MUST triage EVERY alert — none are skipped.

YOUR ROLE:
- Actively investigate each alert as a real analyst working in a SOC would
- Write investigation notes as if documenting for the next shift analyst
- Make definitive decisions based on alert context, not only TI data
- If no TI data is available, apply your expertise to analyze the alert content itself

Available VERDICTs:
- "escalate"      : ACTIVE / CRITICAL threat — L2 attention required NOW (active ransomware, confirmed CVE exploitation, ongoing data exfiltration)
- "create_case"   : Confirmed or high-confidence threat — requires L2 investigation
- "monitor"       : Suspicious but not conclusive — acknowledge and continue monitoring
- "false_positive": Clearly benign — known scanner, internal tool, normal behavior

TRIAGE RULES:
- Alert severity critical/high → minimum "create_case", unless there is STRONG evidence of FP
- Alert severity medium without TI → analyze content: unusual timing? suspicious port? abnormal pattern?
- Alert severity low/info → "create_case" only if there are clear signs of malicious intent
- DO NOT use "false_positive" for high/critical severity without very strong justification
- If unsure between "monitor" vs "create_case", choose "create_case"

Respond ONLY with valid JSON — no markdown outside the JSON:
{
  "verdict": "<escalate|create_case|monitor|false_positive>",
  "triage_notes": "<3-5 sentences in English — write your investigation notes as if for the next shift analyst. Explain what you found, why it is or is not suspicious, and what to watch for>",
  "confidence": <0.0-1.0>,
  "mitre_techniques": ["<T-code: technique name>"],
  "immediate_actions": ["<concrete action to take immediately>"],
  "false_positive_reason": "<reason if FP, null if not FP>",
  "threat_type": "<threat type: brute_force|scan|malware|c2|exfiltration|lateral_movement|privilege_escalation|other|benign>",
  "search_queries": ["<1-3 specific search queries to gather more context — write queries you would type into Google as an analyst wanting to learn more about this threat. Example: 'SSH brute force Linux MITRE T1110 defense 2024', 'Mimikatz LSASS dump detection bypass technique', 'Log4Shell CVE-2021-44228 indicators of compromise'>"]
}

IMPORTANT for search_queries: make queries SPECIFIC and USEFUL — not just the alert name. Think: what would you search online to understand this threat more deeply?"""


async def analyze_alert_with_groq(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    enrichment=None,
    heuristic_mitre: list[str] | None = None,
    search_results: list[dict] | None = None,
    similar_cases: list[dict] | None = None,
    sop_context: list[str] | None = None,
) -> dict:
    """L1 SOC analyst triage. Returns verdict + triage_notes + immediate_actions."""
    api_key = await get_setting("groq_api_key") or GROQ_API_KEY
    model = await get_setting("groq_model", "llama-3.3-70b-versatile")
    enabled = await get_setting("ai_analyst_enabled", "true")

    if not api_key or enabled.lower() == "false":
        return _fallback_verdict(severity)

    # Build TI enrichment context
    enrichment_section = ""
    if enrichment and enrichment.provider_bullets:
        lines = "\n".join(f"  - {b}" for b in enrichment.provider_bullets[:20])
        enrichment_section = f"\nTHREAT INTEL:\n{lines}"
        if enrichment.overall_risk > 0:
            enrichment_section += f"\nTI risk score: {enrichment.overall_risk:.2f}"
        if enrichment.triage_hints:
            hints = "\n".join(f"  * {h}" for h in enrichment.triage_hints[:5])
            enrichment_section += f"\nTriage hints:\n{hints}"
    else:
        enrichment_section = "\nTHREAT INTEL: Not available — use alert context for analysis."

    mitre_hint = f"\nHeuristic MITRE: {', '.join(heuristic_mitre)}" if heuristic_mitre else ""

    ioc_list = ""
    if enrichment and enrichment.iocs:
        iocs = [f"{i.type.value}:{i.value}" for i in enrichment.iocs[:10]]
        ioc_list = f"\nExtracted IOCs: {', '.join(iocs)}"

    similar_cases_section = ""
    if similar_cases:
        lines = []
        for i, c in enumerate(similar_cases[:3], 1):
            sim_pct = int(float(c.get("similarity", 0)) * 100)
            desc = (c.get("description") or "")[:200]
            lines.append(
                f"{i}. [{c.get('status','?').upper()}] {c.get('title','?')} "
                f"(similarity: {sim_pct}%)\n   {desc}"
            )
        similar_cases_section = "\n\nLEARNINGS FROM PREVIOUS CASES:\n" + "\n".join(lines)

    sop_section = ""
    if sop_context:
        lines = "\n\n".join(f"- {chunk}" for chunk in sop_context[:3])
        sop_section = f"\n\nCOMPANY SOP — INCIDENT RESPONSE GUIDE:\n{lines}"

    prompt = f"""ALERT TO TRIAGE:
Title    : {title}
Severity : {severity}
Source IP: {source_ip or 'unknown'}
Hostname : {hostname or 'unknown'}
Fields   : {json.dumps(decoded_fields, default=str)[:500]}{ioc_list}{mitre_hint}{enrichment_section}{similar_cases_section}{sop_section}

Perform triage and provide your verdict as an L1 analyst."""

    try:
        result = await _groq_post(api_key, {
            "model": model,
            "messages": [
                {"role": "system", "content": _L1_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.15,
            "max_tokens": 700,
        })
        content = result["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception as e:
        log.error("groq_l1_triage_failed", error=str(e))
        fallback = await _claude_triage(title, severity, source_ip, hostname, decoded_fields)
        if fallback:
            log.info("groq_fallback_used", model="claude-haiku-4-5-20251001")
            return fallback
        return _fallback_verdict(severity)


async def _claude_triage(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
) -> dict | None:
    """Fallback LLM triage via Anthropic Claude when Groq is unavailable."""
    api_key = await get_setting("anthropic_api_key", "") or ANTHROPIC_API_KEY
    enabled = await get_setting("fallback_llm", "false")
    if not api_key or enabled.lower() != "true":
        return None
    try:
        import anthropic as _anthropic
        prompt = (
            f"ALERT TO TRIAGE:\nTitle: {title}\nSeverity: {severity}\n"
            f"Source IP: {source_ip or 'unknown'}\nHostname: {hostname or 'unknown'}\n"
            f"Fields: {json.dumps(decoded_fields, default=str)[:400]}\n\n"
            "Respond ONLY with valid JSON:\n"
            '{"verdict":"<escalate|create_case|monitor|false_positive>",'
            '"triage_notes":"<2-3 sentences in English>",'
            '"confidence":0.7,"mitre_techniques":[],"immediate_actions":[],'
            '"false_positive_reason":null,"threat_type":"other","search_queries":[]}'
        )
        client = _anthropic.AsyncAnthropic(api_key=api_key)
        msg = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        content = msg.content[0].text.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception as exc:
        log.warning("claude_fallback_failed", error=str(exc))
        return None


def _fallback_verdict(severity: str) -> dict:
    """Fallback when Groq is unavailable — deterministic decision based on severity."""
    if severity in ("critical", "high"):
        return {
            "verdict": "create_case",
            "triage_notes": f"AI analyst unavailable. Severity {severity} alert automatically escalated for L2 review.",
            "confidence": 0.5,
            "mitre_techniques": [],
            "immediate_actions": ["Review alert manually", "Verify source IP"],
            "false_positive_reason": None,
            "threat_type": "other",
        }
    return {
        "verdict": "monitor",
        "triage_notes": f"AI analyst unavailable. Severity {severity} alert acknowledged for continued monitoring.",
        "confidence": 0.3,
        "mitre_techniques": [],
        "immediate_actions": ["Monitor for similar alerts"],
        "false_positive_reason": None,
        "threat_type": "other",
    }


_CAMPAIGN_SYSTEM_PROMPT = """You are a senior SOC Threat Intelligence Analyst. You are given a chronological timeline of security alerts and UEBA anomalies all related to the same IP address or hostname within the last 24 hours.

Your job is to:
1. Understand the FULL attack story — not individual alerts, but the campaign as a whole
2. Identify which stage of the kill chain this represents
3. Map to MITRE ATT&CK techniques across the full timeline
4. Assess attacker intent and sophistication
5. Recommend concrete response actions

Respond ONLY with valid JSON — no markdown outside the JSON:
{
  "kill_chain_stage": "<one of: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration, Impact, Unknown>",
  "attacker_intent": "<1-2 sentences about what the attacker is trying to achieve>",
  "narrative": "<3-5 sentences in English: full attack story, timeline, how alerts connect>",
  "mitre_techniques": ["<T-code: name>", ...],
  "recommended_actions": ["<specific action>", ...],
  "confidence": <0.0-1.0>,
  "sophistication": "<low|medium|high|apt>"
}"""


async def analyze_campaign_with_groq(
    source_ip: str | None,
    hostname: str | None,
    timeline: str,
    alert_count: int,
) -> dict | None:
    """Analyze a full attack campaign timeline and return structured assessment."""
    api_key = await get_setting("groq_api_key") or GROQ_API_KEY
    model = await get_setting("groq_model", "llama-3.3-70b-versatile")
    enabled = await get_setting("ai_analyst_enabled", "true")

    if not api_key or enabled.lower() == "false":
        return None

    entity = source_ip or hostname or "unknown"
    prompt = f"""Entity under analysis: {entity}
Total alerts in 24h window: {alert_count}

CHRONOLOGICAL ATTACK TIMELINE:
{timeline}

Analyze this as a complete attack campaign. What is the full story?"""

    try:
        result = await _groq_post(api_key, {
            "model": model,
            "messages": [
                {"role": "system", "content": _CAMPAIGN_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1024,
        })
        content = result["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception as e:
        log.error("groq_campaign_failed", error=str(e))
        return None
