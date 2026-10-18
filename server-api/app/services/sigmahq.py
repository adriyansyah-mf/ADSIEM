# server-api/app/services/sigmahq.py
"""Import the SigmaHQ ruleset (github.com/SigmaHQ/sigma release packages) into the rules table.

Idempotent: rules are keyed by their Sigma id (source="sigmahq", external_id).
Re-importing updates rules whose content still matches what was last imported
and leaves locally edited ones alone, so an analyst's tuning survives updates.
New rules are enabled only when their level/status pass the requested policy
and a log source on this platform can feed them.
"""
import io
import zipfile
from dataclasses import dataclass, field

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Rule
from app.services.rule_content import (
    collected, compile_errors, content_hash, first_doc, known_log_types, rule_metadata,
)

log = structlog.get_logger()

RULESETS = {
    "core": "sigma_core.zip",
    "core+": "sigma_core+.zip",
    "core++": "sigma_core++.zip",
    "emerging_threats": "sigma_emerging_threats_addon.zip",
    "all": "sigma_all_rules.zip",
}
_RELEASE_URL = "https://github.com/SigmaHQ/sigma/releases/{path}/{asset}"
_MAX_DOWNLOAD = 64 * 1024 * 1024
_MAX_MEMBERS = 20_000
_MAX_UNCOMPRESSED = 256 * 1024 * 1024
_SKIP_STATUSES = {"deprecated", "unsupported"}


class SigmaHQError(Exception):
    pass


async def download(ruleset: str, release: str = "latest") -> tuple[bytes, str]:
    """(zip bytes, release tag) for a SigmaHQ release package."""
    asset = RULESETS.get(ruleset)
    if asset is None:
        raise SigmaHQError(f"unknown ruleset '{ruleset}' (one of: {', '.join(RULESETS)})")
    if release != "latest" and not release.replace("-", "").isalnum():
        raise SigmaHQError(f"invalid release tag '{release}'")
    path = "latest/download" if release == "latest" else f"download/{release}"
    url = _RELEASE_URL.format(path=path, asset=asset)
    async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
        async with client.stream("GET", url) as resp:
            if resp.status_code != 200:
                raise SigmaHQError(f"download failed: HTTP {resp.status_code} for {url}")
            # .../releases/download/<tag>/<asset> after the redirect
            parts = str(resp.url).split("/")
            tag = parts[-2] if len(parts) >= 2 and release == "latest" else release
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > _MAX_DOWNLOAD:
                    raise SigmaHQError("download exceeds 64 MB")
    return bytes(buf), tag


def read_rules(zip_bytes: bytes) -> list[str]:
    """The .yml rule files in a SigmaHQ package (or any zip of Sigma rules)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise SigmaHQError(f"not a zip file: {exc}") from exc
    members = [m for m in zf.infolist() if not m.is_dir() and m.filename.lower().endswith((".yml", ".yaml"))]
    if len(members) > _MAX_MEMBERS:
        raise SigmaHQError(f"too many files in archive ({len(members)})")
    if sum(m.file_size for m in members) > _MAX_UNCOMPRESSED:
        raise SigmaHQError("archive expands beyond 256 MB")
    out = []
    for m in members:
        try:
            out.append(zf.read(m).decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return out


@dataclass
class ImportStats:
    release: str
    total: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    kept_local_edits: int = 0
    rejected: int = 0
    enabled: int = 0
    not_collected: int = 0
    rejected_examples: list[str] = field(default_factory=list)


async def import_rules(
    db: AsyncSession, contents: list[str], release: str,
    enable_levels: list[str], enable_statuses: list[str],
) -> ImportStats:
    stats = ImportStats(release=release)
    log_types = await known_log_types(db)
    existing = {
        r.external_id: r for r in (await db.execute(select(Rule).where(Rule.source == "sigmahq"))).scalars()
    }
    levels = {lv.lower() for lv in enable_levels}
    statuses = {s.lower() for s in enable_statuses}

    seen: set[str] = set()
    for content in contents:
        doc = first_doc(content)
        rule_id = str(doc.get("id") or "").strip()[:255]
        status = str(doc.get("status") or "").lower()
        is_rule = "detection" in doc or "correlation" in doc
        if not rule_id or not is_rule or status in _SKIP_STATUSES or rule_id in seen:
            continue
        seen.add(rule_id)
        stats.total += 1
        errors = compile_errors(content)
        if errors:
            stats.rejected += 1
            if len(stats.rejected_examples) < 10:
                stats.rejected_examples.append(errors[0][:300])
            continue

        meta = rule_metadata(content)
        new_hash = content_hash(content)
        row = existing.get(rule_id)
        if row is not None:
            if row.upstream_hash == new_hash:
                stats.unchanged += 1
            elif row.upstream_hash and content_hash(row.content) != row.upstream_hash:
                stats.kept_local_edits += 1
            else:
                for k, v in meta.items():
                    setattr(row, k, v)
                row.content, row.upstream_hash, row.sigma_status = content, new_hash, status or None
                row.version = (row.version or 1) + 1
                stats.updated += 1
            continue

        is_collected = collected(content, log_types)
        enable = is_collected and meta["level"] in levels and (status in statuses or not status)
        stats.not_collected += 0 if is_collected else 1
        stats.enabled += 1 if enable else 0
        db.add(Rule(
            title=meta.get("title", "Untitled"), description=meta.get("description"), content=content,
            level=meta["level"], tags=meta["tags"], mitre_tags=meta["mitre_tags"], is_enabled=enable,
            group_id=None, source="sigmahq", external_id=rule_id, sigma_status=status or None,
            upstream_hash=new_hash,
        ))
        stats.created += 1

    await db.commit()
    log.info("sigmahq_imported", **{k: v for k, v in stats.__dict__.items() if k != "rejected_examples"})
    return stats
