# backend/app/database.py
"""
Async PostgreSQL database engine and session factory.

Supports two configuration modes:
  1. DATABASE_URL  — a full connection string (preferred for Neon, Supabase, etc.)
  2. Individual    — POSTGRES_HOST / USER / PASSWORD / DB env vars (Docker Compose)

Neon requires SSL (sslmode=require). asyncpg handles this via the `ssl=True`
connect_arg when the URL contains the neon.tech hostname, or when
DATABASE_URL already includes ?sslmode=require.
"""

import os
import logging
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Build the asyncpg-compatible connection URL
#
# Neon supplies a standard postgres:// URL with ?sslmode=require.
# asyncpg does NOT understand the ?sslmode query-param — instead it needs
# ssl=True passed as a connect_arg. We strip the param and add the arg.
# ---------------------------------------------------------------------------

def _build_async_url() -> tuple[str, dict]:
    """
    Returns (async_url, connect_args) ready for create_async_engine().

    Priority:
      1. DATABASE_URL env var  (Neon / any full connection string)
      2. Individual POSTGRES_* env vars  (Docker Compose local stack)
    """
    raw_url = os.environ.get("DATABASE_URL", "").strip()

    if raw_url:
        # ── Mode 1: full URL (Neon / Railway / Supabase / etc.) ─────────────
        parsed = urlparse(raw_url)

        # Replace scheme so SQLAlchemy uses asyncpg driver
        scheme = "postgresql+asyncpg"

        # Strip ?sslmode from the query string — asyncpg doesn't accept it
        query_params = parse_qs(parsed.query)
        ssl_required = query_params.pop("sslmode", ["disable"])[0] in ("require", "verify-ca", "verify-full")
        new_query = urlencode({k: v[0] for k, v in query_params.items()})

        async_url = urlunparse((
            scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

        connect_args = {"ssl": True} if ssl_required else {}
        log.info("Database: using DATABASE_URL (host=%s, ssl=%s)", parsed.hostname, ssl_required)

    else:
        # ── Mode 2: individual env vars (Docker Compose) ─────────────────────
        host = os.environ["POSTGRES_HOST"]
        port = os.environ.get("POSTGRES_PORT", "5432")
        db   = os.environ["POSTGRES_DB"]
        user = os.environ["POSTGRES_USER"]
        pw   = os.environ["POSTGRES_PASSWORD"]

        async_url    = f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db}"
        connect_args = {}
        log.info("Database: using individual POSTGRES_* env vars (host=%s)", host)

    return async_url, connect_args


DATABASE_URL, _CONNECT_ARGS = _build_async_url()

engine = create_async_engine(
    DATABASE_URL,
    echo=(os.environ.get("APP_DEBUG", "false").lower() == "true"),
    pool_pre_ping=True,
    poolclass=NullPool,          # Required for async — no persistent pool
    connect_args=_CONNECT_ARGS,  # ssl=True for Neon
)

# Reusable session factory — inject via FastAPI's Depends()
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


async def get_db() -> AsyncSession:
    """
    FastAPI dependency that yields a database session per request
    and guarantees the session is closed even on error.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Create all tables on startup (idempotent).
    In production prefer Alembic migrations instead.
    """
    # Import models so SQLAlchemy registers them with Base.metadata
    from . import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("Database tables verified / created.")
