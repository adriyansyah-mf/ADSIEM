"""API-owned inbox schema; caller holds the existing startup advisory lock."""
from app.core.database import engine
from app.models.models import EvidenceGroupUsage, EvidenceInbox


async def migrate_evidence() -> None:
    async with engine.begin() as connection:
        for table in (EvidenceInbox.__table__, EvidenceGroupUsage.__table__):
            await connection.run_sync(lambda sync, table=table: table.create(sync, checkfirst=True))
