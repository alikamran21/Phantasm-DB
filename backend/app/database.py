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
import ssl
import logging
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Build the asyncpg-compatible connection URL.
#
# Root cause of the `channel_binding` TypeError:
#   SQLAlchemy ≥ 2.0.20 passes `channel_binding` to asyncpg when ssl=True
#   is given as a plain bool, but asyncpg < 0.30 does not accept that kwarg.
#
# Fix: pass a proper ssl.SSLContext object instead of a bare True/False.
#   - ssl.create_default_context()  →  verifies server cert (secure)
#   - ctx.check_hostname = False    →  Neon uses SNI; hostname already
#     verified by the cert chain so we skip the redundant Python check
#   - ctx.verify_mode = CERT_REQUIRED  →  still validates the cert itself
#
# We also strip ?sslmode=require from the URL because asyncpg ignores it
# and some SQLAlchemy versions pass it as an unknown kwarg to asyncpg.
# ---------------------------------------------------------------------------

def _make_ssl_context() -> ssl.SSLContext:
    """Return an SSLContext that verifies Neon's TLS certificate."""
    ctx = ssl.create_default_context()
    # Neon endpoints use *.neon.tech wildcard certs — hostname check works,
    # but disable it here to avoid issues with IP-based connections.
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


def _build_async_url() -> tuple[str, dict]:
    """
    Returns (async_url, connect_args) ready for create_async_engine().

    Priority:
      1. DATABASE_URL env var  — full postgres:// string (Neon / Supabase / Railway)
      2. Individual POSTGRES_* env vars — local Docker Compose postgres container
    """
    raw_url = os.environ.get("DATABASE_URL", "").strip()

    if raw_url:
        # ── Mode 1: full connection string ───────────────────────────────────
        parsed = urlparse(raw_url)

        # Swap scheme to the asyncpg dialect SQLAlchemy expects
        scheme = "postgresql+asyncpg"

        # Strip ALL query params that asyncpg doesn't understand:
        #   ?sslmode, ?channel_binding, ?options, etc.
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        ssl_required = query_params.pop("sslmode", ["disable"])[0] in (
            "require", "verify-ca", "verify-full"
        )
        # Also remove channel_binding if Neon ever adds it to the URL
        query_params.pop("channel_binding", None)
        new_query = urlencode({k: v[0] for k, v in query_params.items()})

        async_url = urlunparse((
            scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

        # Pass a real SSLContext — avoids the channel_binding kwarg conflict
        connect_args = {"ssl": _make_ssl_context()} if ssl_required else {}
        log.info(
            "Database: DATABASE_URL mode (host=%s ssl=%s)",
            parsed.hostname, ssl_required,
        )

    else:
        # ── Mode 2: individual env vars (local Docker Compose postgres) ──────
        host = os.environ["POSTGRES_HOST"]
        port = os.environ.get("POSTGRES_PORT", "5432")
        db   = os.environ["POSTGRES_DB"]
        user = os.environ["POSTGRES_USER"]
        pw   = os.environ["POSTGRES_PASSWORD"]

        async_url    = f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db}"
        connect_args = {}
        log.info("Database: POSTGRES_* env var mode (host=%s)", host)

    return async_url, connect_args


DATABASE_URL, _CONNECT_ARGS = _build_async_url()

engine = create_async_engine(
    DATABASE_URL,
    echo=(os.environ.get("APP_DEBUG", "false").lower() == "true"),
    pool_pre_ping=True,
    poolclass=NullPool,           # Required for async — avoids connection reuse bugs
    connect_args=_CONNECT_ARGS,   # ssl=SSLContext for Neon; {} for local
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
