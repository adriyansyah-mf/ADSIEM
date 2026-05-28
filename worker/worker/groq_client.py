# worker/worker/groq_client.py
import json
import httpx
import structlog
from worker.config import GROQ_API_KEY
from worker.settings_cache import get_setting

log = structlog.get_logger()
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

_L1_SYSTEM_PROMPT = """Kamu adalah SOC Analyst L1 yang sedang bertugas. Kamu WAJIB melakukan triage pada SETIAP alert — tidak ada yang dilewati.

PERAN KAMU:
- Investigasi setiap alert secara aktif, seperti analis nyata yang bekerja di SOC
- Tulis catatan investigasi seolah kamu mendokumentasikan untuk shift berikutnya
- Buat keputusan yang tegas berdasarkan konteks alert, bukan hanya TI data
- Jika tidak ada TI data, gunakan keahlianmu untuk menganalisis konten alert itu sendiri

VERDICT yang tersedia:
- "escalate"     : Ancaman AKTIF / KRITIS — butuh perhatian L2 SEKARANG (ransomware aktif, eksploitasi CVE yang terkonfirmasi, exfiltration data sedang berlangsung)
- "create_case"  : Ancaman terkonfirmasi atau high-confidence — perlu investigasi L2
- "monitor"      : Mencurigakan tapi belum konklusif — acknowledge, pantau lebih lanjut
- "false_positive": Jelas benign — scanner yang dikenal, internal tool, perilaku normal

ATURAN TRIAGE:
- Alert severity critical/high → minimal "create_case", kecuali ada bukti KUAT bahwa ini FP
- Alert severity medium tanpa TI → analisis dari konten: apakah waktunya aneh? portnya mencurigakan? polanya tidak normal?
- Alert severity low/info → "create_case" hanya jika ada tanda-tanda jelas berbahaya
- JANGAN gunakan "false_positive" untuk severity high/critical tanpa justifikasi sangat kuat
- Jika ragu antara "monitor" vs "create_case", pilih "create_case"

Respond ONLY dengan valid JSON — tidak ada markdown di luar JSON:
{
  "verdict": "<escalate|create_case|monitor|false_positive>",
  "triage_notes": "<3-5 kalimat dalam Bahasa Indonesia — tulis catatan investigasimu seolah untuk analis shift berikutnya. Jelaskan apa yang kamu temukan, mengapa ini mencurigakan atau tidak, dan apa yang harus diperhatikan>",
  "confidence": <0.0-1.0>,
  "mitre_techniques": ["<T-code: nama teknik>"],
  "immediate_actions": ["<aksi konkret yang harus dilakukan segera>"],
  "false_positive_reason": "<alasan jika FP, null jika bukan FP>",
  "threat_type": "<jenis ancaman: brute_force|scan|malware|c2|exfiltration|lateral_movement|privilege_escalation|other|benign>"
}"""


async def analyze_alert_with_groq(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    enrichment=None,
    heuristic_mitre: list[str] | None = None,
    search_results: list[dict] | None = None,
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
        enrichment_section = "\nTHREAT INTEL: Tidak tersedia — gunakan konteks alert untuk analisis."

    mitre_hint = f"\nHeuristic MITRE: {', '.join(heuristic_mitre)}" if heuristic_mitre else ""

    ioc_list = ""
    if enrichment and enrichment.iocs:
        iocs = [f"{i.type.value}:{i.value}" for i in enrichment.iocs[:10]]
        ioc_list = f"\nIOCs yang diekstrak: {', '.join(iocs)}"

    prompt = f"""ALERT UNTUK DITRIAGE:
Title    : {title}
Severity : {severity}
Source IP: {source_ip or 'tidak diketahui'}
Hostname : {hostname or 'tidak diketahui'}
Fields   : {json.dumps(decoded_fields, default=str)[:500]}{ioc_list}{mitre_hint}{enrichment_section}

Lakukan triage dan berikan verdict-mu sebagai analis L1."""

    try:
        async with httpx.AsyncClient(timeout=35) as client:
            resp = await client.post(
                GROQ_API_URL,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _L1_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.15,
                    "max_tokens": 700,
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
        log.error("groq_l1_triage_failed", error=str(e))
        return _fallback_verdict(severity)


def _fallback_verdict(severity: str) -> dict:
    """Fallback ketika Groq tidak tersedia — buat keputusan deterministik dari severity."""
    if severity in ("critical", "high"):
        return {
            "verdict": "create_case",
            "triage_notes": f"AI analyst tidak tersedia. Alert severity {severity} secara otomatis dieskalasi untuk review L2.",
            "confidence": 0.5,
            "mitre_techniques": [],
            "immediate_actions": ["Review alert secara manual", "Verifikasi source IP"],
            "false_positive_reason": None,
            "threat_type": "other",
        }
    return {
        "verdict": "monitor",
        "triage_notes": f"AI analyst tidak tersedia. Alert severity {severity} diakui untuk pemantauan lebih lanjut.",
        "confidence": 0.3,
        "mitre_techniques": [],
        "immediate_actions": ["Pantau alert serupa"],
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
