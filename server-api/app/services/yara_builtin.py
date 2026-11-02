# server-api/app/services/yara_builtin.py
"""The built-in YARA rule pack (yara/builtin/*.yar in the repository, copied
into the image): one yara_rules row per file, origin "builtin", named
builtin/<file>. Synced at every start, so an upgrade updates the rules; an
analyst's enable/disable choice is kept. Analysts change a built-in rule by
saving a copy under another name, never in place (the next start would
overwrite it)."""
import os
from pathlib import Path

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.models import YaraRule

log = structlog.get_logger()

ORIGIN = "builtin"


def pack_dir() -> Path | None:
    candidates = [os.environ.get("YARA_BUILTIN_DIR", ""), "/app/yara_builtin",
                  str(Path(__file__).resolve().parents[3] / "yara" / "builtin")]
    for c in candidates:
        if c and Path(c).is_dir():
            return Path(c)
    return None


def _description(text: str, stem: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("//") and "rule pack:" in line:
            return "Built-in: " + line.split("rule pack:", 1)[1].strip().rstrip(".")
    return f"Built-in rules: {stem.replace('_', ' ')}"


def load_pack() -> list[dict]:
    d = pack_dir()
    if d is None:
        return []
    out = []
    for f in sorted(d.glob("*.yar")):
        text = f.read_text(encoding="utf-8")
        out.append({"name": f"builtin/{f.stem}", "description": _description(text, f.stem), "content": text})
    return out


# The 7 rules the server used to keep inline and seed on request: replaced by
# the pack. A row still holding exactly this content is removed; one an
# analyst edited is left alone.
LEGACY_NAMES = ("eicar_test", "crypto_miner", "webshell_php", "reverse_shell_bash",
                "ransomware_extension", "ssh_private_key", "credential_dump")


async def sync_builtin_rules(legacy_contents: dict[str, str] | None = None, sessions=None) -> dict:
    pack = load_pack()
    added = updated = removed = 0
    async with (sessions or AsyncSessionLocal)() as db:
        existing = {r.name: r for r in (await db.execute(select(YaraRule))).scalars().all()}
        for p in pack:
            row = existing.get(p["name"])
            if row is None:
                db.add(YaraRule(name=p["name"], description=p["description"], content=p["content"],
                                is_enabled=True, origin=ORIGIN))
                added += 1
            elif row.origin == ORIGIN and (row.content != p["content"] or row.description != p["description"]):
                row.content, row.description = p["content"], p["description"]
                row.validation, row.test_result = None, None  # results named the old content
                updated += 1
        for name, content in (legacy_contents or {}).items():
            row = existing.get(name)
            if row is not None and row.origin == "manual" and row.content == content:
                await db.delete(row)
                removed += 1
        await db.commit()
    if added or updated or removed:
        from app.services import yara_ruleset
        yara_ruleset.invalidate()
    log.info("yara_builtin_synced", rules=len(pack), added=added, updated=updated, removed=removed,
             dir=str(pack_dir()))
    return {"added": added, "updated": updated, "removed": removed, "rules": len(pack)}
