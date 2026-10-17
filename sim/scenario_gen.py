# sim/scenario_gen.py
"""LLM-authored attack scenarios.

Rather than only varying lines inside a hardcoded template, the model is asked
to invent a full scenario: name, MITRE technique, target log source and the raw
lines that express it. Every proposal is then validated against the real decoder
regex for its log type, and any scenario whose lines do not parse is dropped. A
deterministic catalogue is used whenever generation fails, so the simulator never
stops producing traffic.
"""
from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass

import httpx
import structlog

log = structlog.get_logger()

LOG_TYPES = ["linux_auth", "nginx_access_combined", "syslog"]

EXPECTED_ACTIONS: dict[str, list[str]] = {
    "linux_auth": [
        "Failed password",
        "TTY=",
        "USER=root",
        "useradd",
        "su:",
        "session opened",
    ],
    "nginx_access_combined": [
        "HTTP/1.1\"",
        "HTTP/2",
    ],
    "syslog": [
        "CRON",
        "insmod",
        "modprobe",
        "systemd",
        "rm ",
        "shred",
    ],
}

_SYSTEM = """You invent realistic attack scenarios for a defensive security lab.

Return ONLY JSON:
{{
  "name": "<short scenario name>",
  "description": "<one sentence>",
  "mitre": ["T####.###"],
  "log_type": "<one of the allowed log types>",
  "lines": ["<raw log line>", "..."]
}}

Hard rules:
- log_type MUST be one of: {log_types}
- Every line MUST match this regex for that log type:
  linux_auth:         {linux_auth}
  nginx_access_combined: {nginx}
  syslog:             <any plain syslog line>
- Pick the log_type that PRODUCES the attack, not just a plausible one:
  * ssh brute force, invalid-user probing, sudo escalation, su, useradd, PAM
    session  -> linux_auth  (only linux_auth maps sudo lines to event.action
    sudo_command; sending them as syslog yields a generic syslog_message and
    triggers nothing)
  * directory scanning, web login brute force, SQLi/LFI/Log4Shell probes,
    4xx/5xx storms -> nginx_access_combined
  * crontab persistence, kernel module load, log tampering, service restarts
    -> syslog
- Lines must be raw log text a real Linux host would emit, using the placeholder
  values given in the prompt (hostname, attacker IP, timestamp).
- Give exactly {n} lines so threshold-based rules can fire.
- Rotate across DIFFERENT log types and attack stages between calls: web scanning,
  web auth brute force, sudo privilege escalation, user creation persistence,
  crontab persistence, log tampering, kernel module loading, C2 callbacks.
  Do not default to SSH brute force every time.
- Vary users, paths, payloads and user agents. Be realistic, not cartoonish.
- No markdown fences, no prose outside the JSON."""


@dataclass
class ProposedScenario:
    name: str
    description: str
    mitre: list[str]
    log_type: str
    lines: list[str]

    def render_with(self, hostname: str, ip: str, ts: str) -> list[str]:
        out = []
        for line in self.lines:
            out.append(
                line.replace("{{host}}", hostname)
                .replace("{{ip}}", ip)
                .replace("{{ts}}", ts)
            )
        return out


def decoder_patterns() -> dict[str, str]:
    return {
        "linux_auth": r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)",
        "nginx_access_combined": (
            r'(?P<src_ip>\S+)\s+-\s+(?P<user>\S+)\s+\[.*?\]\s+"(?P<method>\S+)\s+'
            r'(?P<request>[^"]+?)\s+HTTP/[^"]+"\s+(?P<status>\d+)'
        ),
    }


def validate(proposal: ProposedScenario, hostname: str, ip: str, ts: str) -> list[str]:
    """Return the lines that actually parse with the target decoder.

    Each log type also asserts the decoded event.action it should yield, so a
    regex match on a line that decodes to nothing useful (e.g. sudo lines sent
    as syslog, which decode to syslog_message rather than sudo_command) is not
    accepted as a successful scenario.
    """
    pattern = decoder_patterns().get(proposal.log_type)
    rendered = proposal.render_with(hostname, ip, ts)
    if not pattern:
        return rendered

    compiled = re.compile(pattern)
    expected = EXPECTED_ACTIONS.get(proposal.log_type)
    kept = []
    for line in rendered:
        m = compiled.search(line)
        if not m:
            continue
        if expected and not any(needle in line for needle in expected):
            continue
        kept.append(line)
    return kept


def _strip_fences(content: str) -> str:
    content = (content or "").strip()
    if content.startswith("```"):
        parts = content.split("```")
        content = parts[1] if len(parts) > 1 else content
        if content.startswith("json"):
            content = content[4:]
    return content.strip()


async def propose(
    *,
    base_url: str,
    api_key: str,
    model: str,
    hostname: str,
    ip: str,
    ts: str,
    n: int = 6,
    avoid: list[str] | None = None,
    hint_log_type: str | None = None,
    timeout: float = 60.0,
) -> ProposedScenario | None:
    if not api_key:
        return None

    patterns = decoder_patterns()
    system = _SYSTEM.format(
        log_types=", ".join(LOG_TYPES),
        linux_auth=patterns["linux_auth"],
        nginx=patterns["nginx_access_combined"],
        n=n,
    )
    user = (
        f"hostname placeholder: {{{{host}}}} -> {hostname}\n"
        f"attacker ip placeholder: {{{{ip}}}} -> {ip}\n"
        f"timestamp placeholder: {{{{ts}}}} -> {ts}\n"
        f"Already used scenario names (pick something different): {avoid or []}\n"
        f"Prefer this log type if it has been underused: {hint_log_type}"
    )

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "max_tokens": 1200,
                    "temperature": 1.0,
                },
            )
            resp.raise_for_status()
            obj, _ = json.JSONDecoder().raw_decode(resp.text)
            content = obj["choices"][0]["message"]["content"]
    except Exception as exc:
        log.warning("scenario_proposal_failed", error=str(exc))
        return None

    try:
        data = json.loads(_strip_fences(content))
    except (json.JSONDecodeError, ValueError):
        log.warning("scenario_proposal_not_json")
        return None

    log_type = str(data.get("log_type", "")).strip()
    if log_type not in LOG_TYPES:
        log.warning("scenario_bad_log_type", log_type=log_type)
        return None

    raw_lines = data.get("lines") or []
    if not isinstance(raw_lines, list) or not raw_lines:
        return None

    proposal = ProposedScenario(
        name=str(data.get("name") or "generated scenario")[:120],
        description=str(data.get("description") or "")[:400],
        mitre=[str(m) for m in (data.get("mitre") or [])][:6],
        log_type=log_type,
        lines=[str(x) for x in raw_lines][:12],
    )

    valid = validate(proposal, hostname, ip, ts)
    if not valid:
        log.warning("scenario_rejected_unparseable", name=proposal.name, log_type=log_type)
        return None
    if len(valid) < len(proposal.lines):
        log.info("scenario_partially_valid", name=proposal.name, kept=len(valid), total=len(proposal.lines))
        proposal.lines = [ln for ln in proposal.lines if ln in set(valid)]

    return proposal
