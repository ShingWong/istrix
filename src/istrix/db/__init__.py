"""iStrix database layer — SQLAlchemy async engine and session management."""

import os

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from istrix.db.models import Base

DATABASE_URL = os.environ.get(
    "ISTRIX_DB_URL",
    "postgresql+asyncpg://istrix:istrix@localhost/istrix",
)
DATABASE_URL_SYNC = os.environ.get(
    "ISTRIX_DB_URL_SYNC",
    "postgresql+psycopg2://istrix:istrix@localhost/istrix",
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=20)
sync_engine = None  # lazy init for migrations

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
