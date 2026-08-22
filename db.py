"""
Database session and connection management using Async SQLAlchemy.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from config import settings

# Engine configuration
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    pool_pre_ping=True,
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides an asynchronous database session.
    Automatically commits or rolls back on exception and closes the session.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Creates all database tables defined in models.py if they do not exist.
    """
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # SQLite schema migration fallback for existing databases
        _migrations = [
            "ALTER TABLE cases ADD COLUMN analysis_complete BOOLEAN DEFAULT 1",
            "ALTER TABLE cases ADD COLUMN threat_dna TEXT",
            "ALTER TABLE cases ADD COLUMN campaign_id TEXT",
            "ALTER TABLE cases ADD COLUMN mutation_class TEXT",
            "ALTER TABLE cases ADD COLUMN intent_class TEXT",
        ]
        for sql in _migrations:
            try:
                await conn.execute(text(sql))
            except Exception:
                pass  # Column already exists — safe to ignore
