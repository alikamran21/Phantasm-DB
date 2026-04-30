# api/admin/flagged-users.py
"""GET /api/admin/flagged-users — all users flagged as attackers. Admin only."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select

from _db import _SessionLocal
from _models import User
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import get_authenticated_user


async def _handle(token: str) -> tuple[int, dict]:
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}
        if user.role.value != "admin":
            return 403, {"detail": "Admin access required."}

        result  = await db.execute(
            select(User).where(User.is_flagged_as_attacker == True)  # noqa
        )
        flagged = result.scalars().all()

        return 200, {
            "flagged_users": [
                {
                    "id":                    u.id,
                    "email":                 u.email,
                    "role":                  u.role.value,
                    "failed_login_count":    u.failed_login_count,
                    "last_login_ip":         u.last_login_ip,
                    "is_flagged_as_attacker":u.is_flagged_as_attacker,
                }
                for u in flagged
            ]
        }


def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight()
    if request.method != "GET":
        return err("Method not allowed.", 405)

    token  = get_bearer_token(request)
    status, data = asyncio.run(_handle(token))
    return {"statusCode": status, "headers": cors_headers("GET, OPTIONS"), "body": json.dumps(data)}
