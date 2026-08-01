# worker/worker/database.py
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from worker.config import DATABASE_URL

# Default pool_size=5/max_overflow=10 gets exhausted under real load — the worker
# runs many concurrent background loops sharing this one pool (per-alert AI tasks,
# hunt_loop, campaign_analyzer, SOAR actions, webhook dispatch, maintenance,
# report_sender, settings_cache), each holding a session at once.
engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True, pool_size=10, max_overflow=15)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
