from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

# See worker/worker/database.py — same default-pool-exhaustion issue, smaller
# bump here since server-api's sessions are short-lived (request/response), not
# long-running background loops.
engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True, pool_size=8, max_overflow=7)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

class Base(DeclarativeBase):
    pass

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
