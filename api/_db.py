# api/_db.py
"""
Shared database engine for Vercel serverless functions.
NullPool — no persistent connections between invocations.
SSL context built explicitly to avoid asyncpg channel_binding TypeError.
"""
import os
import ssl
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool


def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


def _build_url() -> tuple[str, dict]:
    raw    = os.environ["DATABASE_URL"].strip()
    parsed = urlparse(raw)
    qp     = parse_qs(parsed.query, keep_blank_values=True)
    ssl_ok = qp.pop("sslmode", ["disable"])[0] in ("require", "verify-ca", "verify-full")
    qp.pop("channel_binding", None)
    url = urlunparse((
        "postgresql+asyncpg",
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode({k: v[0] for k, v in qp.items()}),
        parsed.fragment,
    ))
    return url, ({"ssl": _make_ssl_ctx()} if ssl_ok else {})


_url, _connect_args = _build_url()

_engine = create_async_engine(
    _url,
    poolclass    = NullPool,
    connect_args = _connect_args,
    echo         = False,
)

_SessionLocal = async_sessionmaker(
    bind          = _engine,
    class_        = AsyncSession,
    expire_on_commit = False,
    autoflush     = False,
    autocommit    = False,
)


class Base(DeclarativeBase):
    pass


async def init_db() -> None:
    """Create all tables. Import all models first so metadata is populated."""
    import _models  # noqa: F401 — registers all ORM classes with Base.metadata
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
