# sim/main.py
"""Continuous attack simulator for a SIEM lab.

Each cycle asks the LLM to invent a fresh attack scenario (name, MITRE
technique, target log source and raw lines). The proposal is validated against
the real decoder regex for its log type; anything that would not parse is
dropped and the deterministic catalogue is used instead, so the simulator keeps
producing traffic even when the model is down or hallucinating.

Lines are pushed through /api/ingest/log as a real agent would, so simulated
traffic travels the same decode -> Sigma -> alert -> SOAR path as production.
"""
from __future__ import annotations

import asyncio
import os
import random
import sys
from datetime import datetime, timezone

import httpx
import structlog

from scenario_gen import propose
from scenarios import SCENARIOS, by_key

log = structlog.get_logger()

API_URL = os.environ.get("SIM_API_URL", "http://server-api:8000")
AGENT_TOKEN = os.environ.get("SIM_AGENT_TOKEN", "")
AGENT_ID = os.environ.get("SIM_AGENT_ID", "")
HOSTNAME = os.environ.get("SIM_HOSTNAME", "agent-demo")

LLM_BASE_URL = os.environ.get("NINEROUTER_BASE_URL", "http://9router:20128/v1")
LLM_API_KEY = os.environ.get("NINEROUTER_API_KEY", "")
LLM_MODEL = os.environ.get("NINEROUTER_MODEL", "")
LLM_ENABLED = os.environ.get("SIM_LLM_ENABLED", "true").lower() != "false"

INTERVAL = float(os.environ.get("SIM_INTERVAL_SECONDS", "20"))
JITTER = float(os.environ.get("SIM_JITTER_SECONDS", "8"))
ONLY = os.environ.get("SIM_SCENARIOS", "").strip()
ATTACKER_NET = os.environ.get("SIM_ATTACKER_NET", "203.0.113.")

MAX_REMEMBERED = 25
LOG_TYPE_ROTATION = ["linux_auth", "nginx_access_combined", "syslog"]


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")


def _attacker_ip(rng: random.Random) -> str:
    if ATTACKER_NET.endswith("."):
        return f"{ATTACKER_NET}{rng.randint(2, 254)}"
    return ATTACKER_NET


def _catalogue():
    if not ONLY:
        return SCENARIOS
    keys = [k.strip() for k in ONLY.split(",") if k.strip()]
    chosen = [s for s in (by_key(k) for k in keys) if s]
    return chosen or SCENARIOS


async def _ingest(client: httpx.AsyncClient, log_type: str, lines: list[str]) -> int:
    sent = 0
    for line in lines:
        try:
            resp = await client.post(
                f"{API_URL}/api/ingest/log",
                headers={"X-Agent-Token": AGENT_TOKEN},
                json={
                    "agent_id": AGENT_ID,
                    "hostname": HOSTNAME,
                    "log_type": log_type,
                    "raw_message": line,
                    "received_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            if resp.status_code == 202:
                sent += 1
            else:
                log.warning("ingest_rejected", status=resp.status_code, body=resp.text[:200])
        except Exception as exc:
            log.warning("ingest_failed", error=str(exc))
        await asyncio.sleep(0.25)
    return sent


async def _wait_for_api(client: httpx.AsyncClient) -> None:
    for attempt in range(60):
        try:
            r = await client.get(f"{API_URL}/health", timeout=5)
            if r.status_code == 200:
                log.info("api_ready", attempt=attempt)
                return
        except Exception:
            pass
        await asyncio.sleep(3)
    log.error("api_never_became_ready")


async def main() -> int:
    if not AGENT_TOKEN or not AGENT_ID:
        log.error("missing_agent_credentials", have_token=bool(AGENT_TOKEN), have_id=bool(AGENT_ID))
        return 2

    catalogue = _catalogue()
    rng = random.Random()
    seen_names: list[str] = []

    log.info(
        "simulator_starting",
        interval=INTERVAL,
        llm_enabled=LLM_ENABLED,
        model=LLM_MODEL or "<unset>",
        fallback_scenarios=[s.key for s in catalogue],
    )

    async with httpx.AsyncClient(timeout=30) as client:
        await _wait_for_api(client)

        cycle = 0
        while True:
            cycle += 1
            ts = _now_ts()
            ip = _attacker_ip(rng)

            proposal = None
            if LLM_ENABLED:
                hint = LOG_TYPE_ROTATION[cycle % len(LOG_TYPE_ROTATION)]
                proposal = await propose(
                    base_url=LLM_BASE_URL,
                    api_key=LLM_API_KEY,
                    model=LLM_MODEL,
                    hostname=HOSTNAME,
                    ip=ip,
                    ts=ts,
                    n=rng.choice([4, 6, 8]),
                    avoid=seen_names[-MAX_REMEMBERED:],
                    hint_log_type=hint,
                )

            if proposal:
                seen_names.append(proposal.name)
                lines = proposal.render_with(HOSTNAME, ip, ts)
                log_type = proposal.log_type
                name = proposal.name
                mitre = proposal.mitre
                source = "llm"
            else:
                scenario = rng.choice(catalogue)
                lines = scenario.render(rng, HOSTNAME, ip, ts)
                log_type = scenario.log_type
                name = scenario.key
                mitre = scenario.mitre
                source = "catalogue"

            sent = await _ingest(client, log_type, lines)
            log.info(
                "cycle_complete",
                cycle=cycle,
                source=source,
                scenario=name,
                log_type=log_type,
                mitre=mitre,
                lines=len(lines),
                accepted=sent,
                attacker_ip=ip,
            )

            await asyncio.sleep(INTERVAL + rng.uniform(0, JITTER))


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
