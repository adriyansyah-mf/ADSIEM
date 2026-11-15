"""AI skills: the procedures the investigator loads when a case matches them.

A skill is Markdown with a name and a description of when to use it, like an
agent skill: the model is shown every enabled skill's name and description,
and calls load_skill(name) for the full instructions only when it needs them,
so twenty skills cost a few lines of context, not twenty documents.

Built-in skills live in skills/*.md (YAML-ish frontmatter: name, description),
copied into the image and synced at every start: new ones are added enabled,
changed ones updated, an analyst's enable/disable choice is kept. Analysts
change a built-in skill by saving a copy under another name (the next start
would overwrite an edit in place), and add their own (origin "custom")."""
from __future__ import annotations

import os
import re
from pathlib import Path

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.models import AiSkill

log = structlog.get_logger()

BUILTIN = "builtin"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$")
MAX_CONTENT = 40_000
MAX_DESCRIPTION = 1_000
CATALOG_LIMIT = 40  # skills listed to the model; the rest are not offered


def skills_dir() -> Path | None:
    for c in (os.environ.get("AI_SKILLS_DIR", ""), "/app/ai_skills",
              str(Path(__file__).resolve().parents[3] / "skills")):
        if c and Path(c).is_dir():
            return Path(c)
    return None


def parse_skill(text: str) -> dict | None:
    """name, description and content from a skill file with a --- frontmatter."""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.S)
    if not m:
        return None
    meta = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip().strip('"').strip("'")
    if not meta.get("name") or not meta.get("description"):
        return None
    return {"name": meta["name"], "description": meta["description"], "content": m.group(2).strip()}


def load_pack() -> list[dict]:
    d = skills_dir()
    if d is None:
        return []
    out = []
    for f in sorted(d.glob("*.md")):
        skill = parse_skill(f.read_text(encoding="utf-8"))
        if skill is None or not NAME_RE.match(skill["name"]):
            log.warning("ai_skill_file_invalid", file=f.name)
            continue
        out.append(skill)
    return out


async def sync_builtin_skills(sessions=None) -> dict:
    """Add and update the built-in skills; keep analysts' enable/disable and their own skills."""
    pack = load_pack()
    added = updated = removed = 0
    async with (sessions or AsyncSessionLocal)() as db:
        existing = {r.name: r for r in (await db.execute(select(AiSkill))).scalars().all()}
        names = set()
        for s in pack:
            names.add(s["name"])
            row = existing.get(s["name"])
            if row is None:
                db.add(AiSkill(name=s["name"], description=s["description"], content=s["content"],
                               is_enabled=True, origin=BUILTIN))
                added += 1
            elif row.origin == BUILTIN and (row.content != s["content"] or row.description != s["description"]):
                row.content, row.description = s["content"], s["description"]
                updated += 1
        for name, row in existing.items():  # a built-in skill the pack no longer ships
            if row.origin == BUILTIN and name not in names:
                await db.delete(row)
                removed += 1
        await db.commit()
    if added or updated or removed:
        log.info("ai_skills_synced", added=added, updated=updated, removed=removed)
    return {"added": added, "updated": updated, "removed": removed}


async def catalog(db) -> list[tuple[str, str]]:
    """(name, description) of the enabled skills, for the model's system prompt."""
    rows = (await db.execute(select(AiSkill.name, AiSkill.description).where(AiSkill.is_enabled.is_(True))
                             .order_by(AiSkill.name).limit(CATALOG_LIMIT))).all()
    return [(n, d) for n, d in rows]


async def get_enabled(db, name: str) -> AiSkill | None:
    return (await db.execute(select(AiSkill).where(AiSkill.name == name.strip().lower(),
                                                   AiSkill.is_enabled.is_(True)))).scalar_one_or_none()


def catalog_prompt(skills: list[tuple[str, str]]) -> str:
    """The system-prompt section listing the skills ("" when there are none)."""
    if not skills:
        return ""
    lines = "\n".join(f"- {name}: {desc}" for name, desc in skills)
    return ("\n\nSkills: proven procedures for kinds of attack, written by this SOC. When the case matches "
            "one, call load_skill with its name before you plan the collection, and follow it: adapt it to "
            "what the evidence shows, skip steps that cannot apply, and still cite evidence for every claim "
            "(a skill says what to check, it is not evidence). Load only the ones that fit.\n" + lines)
