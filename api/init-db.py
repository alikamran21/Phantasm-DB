# api/init-db.py
import os as _os, sys as _sys
_lib = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'lib')
for _p in [_lib, '/var/task/lib']:
    if _os.path.isdir(_p) and _p not in _sys.path:
        _sys.path.insert(0, _p)

"""
POST /api/init-db
Creates all DB tables and seeds the admin account.
Protect with X-Init-Secret header. Call once after first Vercel deploy.
"""

import asyncio, json, os, sys

from _db import _SessionLocal, init_db
from _models import ProductionUser, GlobalIdentity, UserRole
from _auth_utils import hash_password
from _handler_base import cors_headers, err, preflight
from sqlalchemy import select

INIT_SECRET = os.environ.get("INIT_SECRET", "")


async def _handle(provided_secret: str) -> tuple[int, dict]:
    if INIT_SECRET and provided_secret != INIT_SECRET:
        return 403, {"detail": "Invalid or missing X-Init-Secret header."}

    await init_db()

    admin_email    = os.environ.get("ADMIN_SEED_EMAIL", "")
    admin_password = os.environ.get("ADMIN_SEED_PASSWORD", "")
    seeded = False

    if admin_email and admin_password:
        async with _SessionLocal() as db:
            result = await db.execute(
                select(ProductionUser).where(ProductionUser.role == UserRole.admin).limit(1)
            )
            if not result.scalar_one_or_none():
                # Create GlobalIdentity root row first
                gi = GlobalIdentity(ip_address="127.0.0.1", risk_score=0.0)
                db.add(gi)
                await db.flush()

                admin = ProductionUser(
                    identity_id   = gi.identity_id,
                    username      = "admin",
                    email         = admin_email,
                    password_hash = hash_password(admin_password),
                    role          = UserRole.admin,
                    mfa_enabled   = True,
                    is_active     = True,
                )
                db.add(admin)
                await db.commit()
                seeded = True

    return 200, {
        "detail":        "Database initialised successfully.",
        "tables_created": True,
        "admin_seeded":  seeded,
        "admin_email":   admin_email if seeded else "already existed or not configured",
    }


def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    provided = (request.headers or {}).get("x-init-secret", "")
    status, data = asyncio.run(_handle(provided))
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps(data)}
