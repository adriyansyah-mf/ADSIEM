# worker/worker/seeder.py
import glob
import os
import yaml
import structlog
from sqlalchemy import select
from worker.config import DECODERS_DIR, RULES_DIR
from worker.database import AsyncSessionLocal
from worker.models import Decoder, Rule

log = structlog.get_logger()

async def seed_if_empty() -> None:
    async with AsyncSessionLocal() as db:
        await _upsert_decoders(db)
        await _upsert_rules(db)
        await db.commit()

async def _upsert_decoders(db) -> None:
    pattern = os.path.join(DECODERS_DIR, "*.yaml")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path) as f:
                content = f.read()
            d = yaml.safe_load(content)
            name = d["name"]
            existing = (await db.execute(select(Decoder).where(Decoder.name == name))).scalar_one_or_none()
            if existing:
                continue
            db.add(Decoder(
                name=name,
                log_type=d["log_type"],
                content=content,
                priority=d.get("priority", 100),
                is_enabled=d.get("enabled", True),
            ))
            log.info("decoder_seeded", name=name)
        except Exception as exc:
            log.error("decoder_seed_failed", path=path, error=str(exc))

async def _upsert_rules(db) -> None:
    pattern = os.path.join(RULES_DIR, "*.yaml")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path) as f:
                content = f.read()
            d = yaml.safe_load(content)
            title = d.get("title", "Untitled")
            existing = (await db.execute(select(Rule).where(Rule.title == title))).scalar_one_or_none()
            if existing:
                continue
            db.add(Rule(
                title=title,
                description=d.get("description"),
                content=content,
                level=d.get("level", "medium"),
                tags=d.get("tags", []),
                mitre_tags=[t for t in d.get("tags", []) if t.startswith("attack.")],
                is_enabled=True,
                group_id=None,
            ))
            log.info("rule_seeded", title=title)
        except Exception as exc:
            log.error("rule_seed_failed", path=path, error=str(exc))
