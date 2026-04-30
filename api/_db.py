# api/_db.py
"""
Shared database engine for Vercel serverless functions.

Vercel Python functions are stateless — each invocation may be a fresh
process.  We use NullPool so SQLAlchemy never tries to reuse a connection
across invocations, and we build the engine lazily on first import.

All API function files import get_db() and _engine from here.
"""
import os
import ssl
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool


# ---------------------------------------------------------------------------
# SSL context for Neon (avoids asyncpg channel_binding TypeError)
# ---------------------------------------------------------------------------
def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


# ---------------------------------------------------------------------------
# Build async URL from DATABASE_URL env var
# ---------------------------------------------------------------------------
def _build_url() -> tuple[str, dict]:
    raw = os.environ["DATABASE_URL"].strip()
    parsed = urlparse(raw)

    qp = parse_qs(parsed.query, keep_blank_values=True)
    ssl_needed = qp.pop("sslmode", ["disable"])[0] in ("require", "verify-ca", "verify-full")
    qp.pop("channel_binding", None)

    url = urlunparse((
        "postgresql+asyncpg",
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode({k: v[0] for k, v in qp.items()}),
        parsed.fragment,
    ))
    connect_args = {"ssl": _make_ssl_ctx()} if ssl_needed else {}
    return url, connect_args


_url, _connect_args = _build_url()

_engine = create_async_engine(
    _url,
    poolclass=NullPool,
    connect_args=_connect_args,
    echo=False,
)

_SessionLocal = async_sessionmaker(
    bind=_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncSession:
    async with _SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables (called once from api/init.py)."""
    from _models import User, AuditLog, OTPRequest  # noqa: F401
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
