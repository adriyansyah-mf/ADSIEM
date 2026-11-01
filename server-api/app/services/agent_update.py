# server-api/app/services/agent_update.py
"""Agent self-update rollouts.

Packages are the files in PACKAGES_DIR that have a `<file>.sig` next to them
(made by `siem-update-sign`, agent/cmd/siem-update-sign). The agent trusts the
signature, not this server: it verifies the manifest with its own keys and the
download against the manifest. With AGENT_UPDATE_PUBLIC_KEYS set the server
checks too, and does not offer a package its keys do not verify.

A group's policy names the target version and the highest ring offered
(`stage`); operators move the stage 0 → 1 → 2. Failed or stalled agents pause
the rollout once there are `max_failures` of them."""
import base64
import binascii
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Agent, AgentUpdatePolicy

PACKAGES_DIR = Path(os.environ.get("PACKAGES_DIR", "/app/packages"))
RINGS = (0, 1, 2)
# an agent that took an offer and has not been heard from since
STALL_AFTER = timedelta(minutes=15)
IN_PROGRESS = ("downloading", "installing")

_cache: dict[str, tuple[tuple, dict | None]] = {}


def _trusted_keys() -> list:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from app.core.config import settings

    keys = []
    for k in (settings.AGENT_UPDATE_PUBLIC_KEYS or "").replace(",", " ").split():
        try:
            keys.append(Ed25519PublicKey.from_public_bytes(base64.b64decode(k, validate=True)))
        except (ValueError, binascii.Error):
            continue  # a malformed key verifies nothing
    return keys


def _verify(signed: dict, raw_manifest: bytes) -> bool | None:
    """True/False against AGENT_UPDATE_PUBLIC_KEYS; None when none are configured."""
    from cryptography.exceptions import InvalidSignature

    from app.core.config import settings

    keys = _trusted_keys()
    if not keys:
        # keys configured but none usable: verify nothing rather than everything
        return False if settings.AGENT_UPDATE_PUBLIC_KEYS.strip() else None
    try:
        sig = base64.b64decode(signed["signature"], validate=True)
    except (KeyError, ValueError, binascii.Error):
        return False
    for k in keys:
        try:
            k.verify(sig, raw_manifest)
            return True
        except InvalidSignature:
            continue
    return False


def _load(sig_path: Path) -> dict | None:
    from app.core.config import settings

    pkg = sig_path.with_name(sig_path.name[: -len(".sig")])
    try:
        # the verdict depends on the configured keys as much as on the files
        stamp = (pkg.stat().st_size, sig_path.stat().st_mtime_ns, pkg.stat().st_mtime_ns,
                 settings.AGENT_UPDATE_PUBLIC_KEYS)
    except OSError:
        return None
    key = str(sig_path)
    if key in _cache and _cache[key][0] == stamp:
        return _cache[key][1]
    entry = None
    try:
        signed = json.loads(sig_path.read_text())
        raw = base64.b64decode(signed["manifest"], validate=True)
        m = json.loads(raw)
        if (m.get("product") == "siem-agent" and m.get("file") == pkg.name and m.get("size") == stamp[0]
                and m.get("format") in ("deb", "rpm", "msi")):
            entry = {"file": pkg.name, "version": m["version"], "os": m["os"], "arch": m["arch"],
                     "format": m["format"], "sha256": m["sha256"], "size": m["size"],
                     "key_id": signed.get("key_id", ""), "verified": _verify(signed, raw),
                     "signed": {"manifest": signed["manifest"], "signature": signed["signature"],
                                "key_id": signed.get("key_id", "")}}
    except (OSError, ValueError, KeyError, TypeError, binascii.Error):
        entry = None
    _cache[key] = (stamp, entry)
    return entry


def signed_packages() -> list[dict]:
    """Current build first, then archive/ (earlier builds kept for rollbacks,
    agent/packaging/publish-packages.sh); a file name appears once."""
    out, seen = [], set()
    for d in (PACKAGES_DIR, PACKAGES_DIR / "archive"):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.sig")):
            if (p := _load(f)) and p["file"] not in seen:
                seen.add(p["file"])
                out.append({**p, "archived": d != PACKAGES_DIR})
    return out


def offerable(p: dict) -> bool:
    return p["verified"] is not False


def find_package(version: str, os_: str, arch: str, fmt: str) -> dict | None:
    for p in signed_packages():
        if (p["version"], p["os"], p["arch"], p["format"]) == (version, os_, arch, fmt) and offerable(p):
            return p
    return None


def package_path(filename: str) -> Path | None:
    """The signed package file an agent may download, or None."""
    for p in signed_packages():
        if p["file"] == filename and offerable(p):
            return PACKAGES_DIR / "archive" / filename if p["archived"] else PACKAGES_DIR / filename
    return None


def classify(agent: Agent, policy: AgentUpdatePolicy, now: datetime) -> str:
    """Where one agent is in its group's rollout."""
    if agent.version == policy.target_version:
        return "updated"
    s = agent.update_status or {}
    if not s:
        return "not_reporting"  # agents before self-update
    if s.get("state") == "unsupported":
        return "unsupported"
    current = s.get("target") == policy.target_version and s.get("revision") == policy.revision
    if current and s.get("state") == "failed":
        return "failed"
    if current and s.get("state") in IN_PROGRESS:
        seen = agent.last_seen_at
        return "stalled" if seen is None or now - seen > STALL_AFTER else "in_progress"
    if agent.update_ring > policy.stage:
        return "waiting_ring"
    if not find_package(policy.target_version, s.get("os", ""), s.get("arch", ""), s.get("kind", "")):
        return "no_package"
    return "pending"


def offer_for(agent: Agent, policy: AgentUpdatePolicy | None, status: dict | None) -> dict | None:
    """The heartbeat's update offer for this agent, if it should update now."""
    if (policy is None or policy.paused or not status or not agent.approved or agent.is_isolated
            or agent.update_ring > policy.stage or agent.version == policy.target_version
            or not status.get("kind")):
        return None
    p = find_package(policy.target_version, status.get("os", ""), status.get("arch", ""), status["kind"])
    if p is None:
        return None
    return {"version": policy.target_version, "revision": policy.revision,
            "url": f"/api/agent/update/package/{p['file']}", "signed": p["signed"]}


async def progress(db: AsyncSession, policy: AgentUpdatePolicy) -> dict:
    """Counts per classify() state, overall and per ring, plus failure samples."""
    now = datetime.now(timezone.utc)
    agents = (await db.execute(select(Agent).where(Agent.group_id == policy.group_id))).scalars().all()
    total: dict[str, int] = {}
    rings: dict[int, dict[str, int]] = {r: {} for r in RINGS}
    failures = []
    for a in agents:
        state = classify(a, policy, now)
        total[state] = total.get(state, 0) + 1
        ring = rings.setdefault(a.update_ring, {})
        ring[state] = ring.get(state, 0) + 1
        if state in ("failed", "stalled") and len(failures) < 20:
            failures.append({"agent_id": str(a.id), "hostname": a.hostname, "state": state,
                             "error": (a.update_status or {}).get("error", "")})
    return {"agents": len(agents), "states": total, "rings": {str(r): c for r, c in sorted(rings.items())},
            "failures": failures}


async def maybe_auto_pause(db: AsyncSession, policy: AgentUpdatePolicy) -> bool:
    """Pause the rollout once max_failures agents failed or stalled on it."""
    if policy.paused:
        return False
    p = await progress(db, policy)
    bad = p["states"].get("failed", 0) + p["states"].get("stalled", 0)
    if bad < policy.max_failures:
        return False
    first = p["failures"][0] if p["failures"] else {}
    reason = (f"{bad} agent(s) failed or stalled updating to {policy.target_version}"
              + (f"; {first.get('hostname')}: {first.get('error')}" if first.get("error") else ""))[:1000]
    res = await db.execute(
        update(AgentUpdatePolicy)
        .where(AgentUpdatePolicy.group_id == policy.group_id, AgentUpdatePolicy.revision == policy.revision,
               AgentUpdatePolicy.paused.is_(False))
        .values(paused=True, pause_reason=reason))
    await db.commit()
    return res.rowcount > 0
