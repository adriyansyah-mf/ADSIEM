# worker/worker/groq_client.py
import json
import httpx
import structlog
from worker.config import GROQ_API_KEY

log = structlog.get_logger()
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.3-70b-versatile"

async def analyze_alert_with_groq(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    search_results: list[dict],
) -> dict:
    """Call Groq to analyze an alert. Returns {should_create_case, reasoning, confidence, ioc_summary}."""
    if not GROQ_API_KEY:
        return {"should_create_case": False, "reasoning": "No GROQ_API_KEY configured", "confidence": 0.0, "ioc_summary": {}}

    search_context = ""
    if search_results:
        items = [f"- {r.get('title','')}: {r.get('content','')[:200]}" for r in search_results[:3]]
        search_context = "Threat intel from search:\n" + "\n".join(items)

    prompt = f"""You are a SOC Analyst L1. Analyze this security alert and decide if it warrants creating a case for L2 review.

Alert: {title}
Severity: {severity}
Source IP: {source_ip or 'unknown'}
Hostname: {hostname or 'unknown'}
Decoded fields: {json.dumps(decoded_fields, default=str)[:500]}
{search_context}

Respond with JSON only, no markdown:
{{
  "should_create_case": <true/false>,
  "reasoning": "<2-3 sentence analysis in Indonesian>",
  "confidence": <0.0-1.0>,
  "ioc_summary": {{
    "source_ip": "<ip or null>",
    "threat_type": "<type or null>",
    "mitre_technique": "<T-code or null>"
  }}
}}

Create a case if: severity is critical/high, OR it matches known attack patterns, OR search intel confirms malicious activity."""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                GROQ_API_URL,
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": 512,
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            # Strip markdown code fences if present
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content)
    except Exception as e:
        log.error("groq_analysis_failed", error=str(e))
        return {"should_create_case": False, "reasoning": f"AI analysis error: {e}", "confidence": 0.0, "ioc_summary": {}}
