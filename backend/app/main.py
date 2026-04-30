# backend/app/main.py
"""
Phantasm-DB — FastAPI application entry point.

Startup sequence:
  1. Load environment variables (injected by Docker Compose / .env).
  2. Initialise the async database engine and run table migrations.
  3. Optionally seed an admin user if none exists.
  4. Mount all routers (auth, routing/portal, health).
  5. Apply global CORS, trusted-host, and GZip middleware.
  6. Start Uvicorn (via Dockerfile CMD).
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .auth import hash_password, router as auth_router
from .database import AsyncSessionLocal, init_db
from .models import User, UserRole
from .routing import router as portal_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

APP_ENV      = os.environ.get("APP_ENV", "production")
DEBUG        = APP_ENV == "development"
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost").split(",")
    if o.strip()
]


# ---------------------------------------------------------------------------
# Lifespan (replaces deprecated @app.on_event)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB on startup; run cleanup on shutdown."""
    log.info("=== Phantasm-DB starting (env=%s) ===", APP_ENV)
    await init_db()
    await _seed_admin()
    yield
    log.info("=== Phantasm-DB shutting down ===")


async def _seed_admin() -> None:
    """
    Create a default admin account on first boot if none exists.
    Credentials are read from environment variables.
    """
    admin_email    = os.environ.get("ADMIN_SEED_EMAIL")
    admin_password = os.environ.get("ADMIN_SEED_PASSWORD")

    if not admin_email or not admin_password:
        log.warning("ADMIN_SEED_EMAIL / ADMIN_SEED_PASSWORD not set — skipping seed.")
        return

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.role == UserRole.admin).limit(1)
        )
        if result.scalar_one_or_none():
            log.info("Admin user already exists — skipping seed.")
            return

        admin = User(
            email         = admin_email,
            password_hash = hash_password(admin_password),
            role          = UserRole.admin,
            full_name     = "System Administrator",
            is_active     = True,
        )
        db.add(admin)
        await db.commit()
        log.info("Seed admin created: %s", admin_email)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title       = "Phantasm-DB API",
    description = (
        "Active-defense backend for Serenity Psychiatric Care EHR. "
        "Features honeypot routing, OTP-based 2FA, and forensic audit logging."
    ),
    version     = "1.0.0",
    debug       = DEBUG,
    lifespan    = lifespan,
    # Disable automatic /docs and /redoc in production
    docs_url    = "/docs"    if DEBUG else None,
    redoc_url   = "/redoc"   if DEBUG else None,
    openapi_url = "/openapi.json" if DEBUG else None,
)


# ---------------------------------------------------------------------------
# Middleware stack (applied in reverse registration order)
# ---------------------------------------------------------------------------

app.add_middleware(GZipMiddleware, minimum_size=1000)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ALLOWED_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers     = ["Authorization", "Content-Type", "X-Request-ID"],
)

# Only enforce in production to avoid breaking local dev
if not DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts = ["*"],   # Tighten to your actual domain in production
    )


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    # Never expose internal details to clients in production
    detail = str(exc) if DEBUG else "An internal server error occurred."
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": detail},
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth_router,   prefix="/api")
app.include_router(portal_router, prefix="/api")


# ---------------------------------------------------------------------------
# Health check (used by Docker Compose healthcheck + load balancers)
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Health"], include_in_schema=DEBUG)
async def health():
    return {"status": "ok", "env": APP_ENV}


@app.get("/", include_in_schema=False)
async def root():
    return {"service": "Phantasm-DB", "version": "1.0.0"}
