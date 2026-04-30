# api/init-db.py
"""
POST /api/init-db
One-time endpoint: creates all DB tables and seeds the admin account.

Protect this with a secret header after first use, or delete it.
Called once via curl after first Vercel deployment.

Usage:
  curl -s -X POST https://YOUR_APP.vercel.app/api/init-db \
    -H "X-Init-Secret: YOUR_INIT_SECRET"
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from _db import _SessionLocal, init_db
from _models import User, UserRole
from _auth_utils import hash_password
from _handler_base import cors_headers, err, preflight
from sqlalchemy import select


INIT_SECRET = os.environ.get("INIT_SECRET", "")


async def _handle(provided_secret: str) -> tuple[int, dict]:
    # Guard — require matching INIT_SECRET env var if set
    if INIT_SECRET and provided_secret != INIT_SECRET:
        return 403, {"detail": "Invalid or missing X-Init-Secret header."}

    # Create all tables
    await init_db()

    # Seed admin account if none exists
    admin_email    = os.environ.get("ADMIN_SEED_EMAIL", "")
    admin_password = os.environ.get("ADMIN_SEED_PASSWORD", "")
    seeded = False

    if admin_email and admin_password:
        async with _SessionLocal() as db:
            result = await db.execute(
                select(User).where(User.role == UserRole.admin).limit(1)
            )
            if not result.scalar_one_or_none():
                admin = User(
                    email         = admin_email,
                    password_hash = hash_password(admin_password),
                    role          = UserRole.admin,
                    full_name     = "System Administrator",
                    is_active     = True,
                )
                db.add(admin)
                await db.commit()
                seeded = True

    return 200, {
        "detail": "Database initialised successfully.",
        "tables_created": True,
        "admin_seeded": seeded,
        "admin_email": admin_email if seeded else "already existed",
    }


def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight()
    if request.method != "POST":
        return err("Method not allowed.", 405)

    provided = (request.headers or {}).get("x-init-secret", "")
    status, data = asyncio.run(_handle(provided))
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps(data)}
