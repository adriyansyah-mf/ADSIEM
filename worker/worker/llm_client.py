# worker/worker/llm_client.py
"""AI analyst LLM calls — routed through a local 9router instance
(https://github.com/decolua/9router), which proxies to whichever provider is
configured in the "combo" selected in its dashboard (currently OpenCode Free,
a headless/no-login free model). 9router exposes an OpenAI-compatible
/v1/chat/completions endpoint, so swapping the underlying provider/model is
just a combo change in the 9router dashboard — no code change needed here."""
import asyncio
import json
import httpx
import structlog
from worker.config import NINEROUTER_API_KEY, NINEROUTER_BASE_URL, NINEROUTER_MODEL
from worker.settings_cache import get_setting

log = structlog.get_logger()

# Max 3 concurrent calls — avoid bursts that trip the combo's own rate limiting
_llm_semaphore = asyncio.Semaphore(3)


_MAX_RATE_LIMIT_WAIT = 20.0  # seconds — cap even if the server asks for longer,
# so one rate-limited alert can't stall the single-consumer queue for a long
# "retry-after" once a combo's quota is exhausted. A quota-exhausted combo won't
# recover within a short wait either way; better to fail fast to the fallback
# verdict and let the hourly backfill loop (worker/ai_consumer.py) retry the
# alert once the quota resets.


async def _llm_post(api_key: str, payload: dict, max_retries: int = 4) -> dict:
    """POST a chat completion to 9router, retrying with exponential backoff on 429."""
    delay = 5.0
    url = f"{NINEROUTER_BASE_URL.rstrip('/')}/chat/completions"
    async with _llm_semaphore:
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=40) as client:
                    resp = await client.post(
                        url,
                        headers={"Authorization": f"Bearer {api_key}",
                                 "Content-Type": "application/json"},
                        json=payload,
                    )
                    if resp.status_code == 429:
                        retry_after = float(resp.headers.get("retry-after", delay))
                        wait = min(max(retry_after, delay), _MAX_RATE_LIMIT_WAIT)
                        log.warning("ninerouter_rate_limited", attempt=attempt + 1,
                                    wait_seconds=wait, server_requested=retry_after)
                        await asyncio.sleep(wait)
                        delay = min(delay * 2, 60)
                        continue
                    resp.raise_for_status()
                    # 9router responds with a text/event-stream body even for
                    # non-streaming requests — a JSON object immediately
                    # followed by a trailing "data: [DONE]" marker with no
                    # separator. raw_decode() parses the leading JSON object
                    # and ignores whatever comes after it.
                    obj, _ = json.JSONDecoder().raw_decode(resp.text)
                    return obj
            except httpx.HTTPStatusError:
                raise
            except Exception as exc:
                if attempt == max_retries - 1:
                    raise
                log.warning("ninerouter_retry", attempt=attempt + 1, error=str(exc))
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)
    raise RuntimeError("9router max retries exceeded")

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


async def analyze_alert_with_ai(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    sigma_context: dict | None = None,
    enrichment=None,
    heuristic_mitre: list[str] | None = None,
    search_results: list[dict] | None = None,
    similar_cases: list[dict] | None = None,
    sop_context: list[str] | None = None,
    feedback_context: list[dict] | None = None,
) -> dict:
    """L1 SOC analyst triage. Returns verdict + triage_notes + immediate_actions."""
    api_key = await get_setting("ninerouter_api_key") or NINEROUTER_API_KEY
    model = await get_setting("ninerouter_model", NINEROUTER_MODEL)
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

    sigma_section = ""
    if sigma_context:
        sigma_section = (
            "\nSIGMA RULE THAT GENERATED THIS ALERT:\n"
            f"{json.dumps(sigma_context, default=str)[:1800]}\n"
            "Explain which rule intent is supported by the observed fields and assess false-positive risk."
        )

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

    feedback_section = ""
    if feedback_context:
        lines = []
        for f in feedback_context[:3]:
            sim_pct = int(float(f.get("similarity", 0)) * 100)
            if f.get("rating") == "incorrect":
                correction = f.get("correct_verdict") or "?"
                note = f" — {f['note']}" if f.get("note") else ""
                lines.append(
                    f"⚠️ An analyst marked a similar AI triage as INCORRECT (similarity: {sim_pct}%). "
                    f"AI said '{f.get('ai_verdict','?')}', should have been '{correction}'{note}"
                )
            else:
                lines.append(
                    f"✓ An analyst confirmed a similar AI triage was CORRECT (similarity: {sim_pct}%): "
                    f"verdict '{f.get('ai_verdict','?')}'"
                )
        feedback_section = "\n\nANALYST FEEDBACK ON PAST SIMILAR TRIAGES (adjust your verdict if it applies here):\n" + "\n".join(lines)

    prompt = f"""ALERT TO TRIAGE:
Title    : {title}
Severity : {severity}
Source IP: {source_ip or 'unknown'}
Hostname : {hostname or 'unknown'}
Fields   : {json.dumps(decoded_fields, default=str)[:500]}{ioc_list}{mitre_hint}{sigma_section}{enrichment_section}{similar_cases_section}{sop_section}{feedback_section}

Perform triage and provide your verdict as an L1 analyst."""

    try:
        result = await _llm_post(api_key, {
            "model": model,
            "messages": [
                {"role": "system", "content": _L1_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.15,
            # 9router's combo model is a reasoning model that spends part of its
            # budget on hidden "reasoning_content" before writing the actual JSON
            # answer — 700 wasn't enough headroom and routinely got cut off
            # mid-answer (finish_reason "length"), so this needs real slack.
            "max_tokens": 2500,
        })
        content = result["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception as e:
        log.error("ai_l1_triage_failed", error=str(e))
        return _fallback_verdict(severity)


def _fallback_verdict(severity: str) -> dict:
    """Fallback when 9router is unavailable — deterministic decision based on severity."""
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


_CAMPAIGN_SYSTEM_PROMPT = """You are a senior SOC Threat Intelligence Analyst. You are given a chronological timeline of security alerts all related to the same IP address or hostname within the last 24 hours.

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


async def analyze_campaign_with_ai(
    source_ip: str | None,
    hostname: str | None,
    timeline: str,
    alert_count: int,
) -> dict | None:
    """Analyze a full attack campaign timeline and return structured assessment."""
    api_key = await get_setting("ninerouter_api_key") or NINEROUTER_API_KEY
    model = await get_setting("ninerouter_model", NINEROUTER_MODEL)
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
        result = await _llm_post(api_key, {
            "model": model,
            "messages": [
                {"role": "system", "content": _CAMPAIGN_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 3000,  # see analyze_alert_with_ai — reasoning model needs real headroom
        })
        content = result["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception as e:
        log.error("ai_campaign_failed", error=str(e))
        return None
