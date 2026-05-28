# worker/worker/groq_client.py
import json
import httpx
import structlog
from worker.config import GROQ_API_KEY
from worker.settings_cache import get_setting

log = structlog.get_logger()
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

_SYSTEM_PROMPT = """You are a SOC Analyst Level 1. Analyze the security alert and supporting threat intel, then decide if it warrants creating a case for L2 review.

Evidence hierarchy (most to least authoritative):
1. Structured TI enrichment bullets (abuseipdb, virustotal, otx, urlhaus, greynoise, whois, geoip)
2. Web search snippets (searxng) — orientation only, corroborate with TI
3. Alert fields (title, decoded_fields)

Respond ONLY with valid JSON — no markdown, no explanation outside JSON:
{
  "should_create_case": <true/false>,
  "reasoning": "<2-3 sentence analysis in Indonesian>",
  "confidence": <0.0-1.0>,
  "ioc_summary": {
    "source_ip": "<ip or null>",
    "threat_type": "<type or null>",
    "mitre_technique": "<T-code or null>"
  }
}

Create a case if: severity is critical/high, OR TI shows malicious indicators, OR enrichment risk >= 0.45."""


async def analyze_alert_with_groq(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    enrichment=None,
    heuristic_mitre: list[str] | None = None,
    # legacy compat
    search_results: list[dict] | None = None,
) -> dict:
    """Call Groq to analyze an alert. Returns {should_create_case, reasoning, confidence, ioc_summary}."""
    api_key = await get_setting("groq_api_key") or GROQ_API_KEY
    model = await get_setting("groq_model", "llama-3.3-70b-versatile")
    enabled = await get_setting("ai_analyst_enabled", "true")

    if not api_key or enabled.lower() == "false":
        return {"should_create_case": False, "reasoning": "AI analyst not configured", "confidence": 0.0, "ioc_summary": {}}

    # Build enrichment section
    enrichment_section = ""
    if enrichment and enrichment.provider_bullets:
        lines = "\n".join(f"  - {b}" for b in enrichment.provider_bullets[:20])
        enrichment_section = f"\nSTRUCTURED_ENRICHMENT:\n{lines}"
        if enrichment.overall_risk > 0:
            enrichment_section += f"\nOverall TI risk score: {enrichment.overall_risk:.2f}"
        if enrichment.triage_hints:
            hints = "\n".join(f"  * {h}" for h in enrichment.triage_hints[:5])
            enrichment_section += f"\nTriage hints:\n{hints}"
    elif search_results:
        # legacy fallback
        items = [f"  - {r.get('title','')}: {r.get('content','')[:200]}" for r in search_results[:3]]
        enrichment_section = "Threat intel from search:\n" + "\n".join(items)

    mitre_hint = ""
    if heuristic_mitre:
        mitre_hint = f"\nHeuristic MITRE hints: {', '.join(heuristic_mitre)}"

    ioc_list = ""
    if enrichment and enrichment.iocs:
        iocs = [f"{i.type.value}:{i.value}" for i in enrichment.iocs[:10]]
        ioc_list = f"\nExtracted IOCs: {', '.join(iocs)}"

    prompt = f"""Alert: {title}
Severity: {severity}
Source IP: {source_ip or 'unknown'}
Hostname: {hostname or 'unknown'}
Decoded fields: {json.dumps(decoded_fields, default=str)[:400]}{ioc_list}{mitre_hint}{enrichment_section}"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                GROQ_API_URL,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 512,
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content)
    except Exception as e:
        log.error("groq_analysis_failed", error=str(e))
        return {"should_create_case": False, "reasoning": f"AI analysis error: {e}", "confidence": 0.0, "ioc_summary": {}}


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
  "narrative": "<3-5 sentences in Indonesian: full attack story, timeline, how alerts connect>",
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
        async with httpx.AsyncClient(timeout=45) as client:
            resp = await client.post(
                GROQ_API_URL,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _CAMPAIGN_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content)
    except Exception as e:
        log.error("groq_campaign_failed", error=str(e))
        return None
