# api/admin/flagged-users.py
"""GET /api/admin/flagged-users — Admin only."""
import asyncio, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select
from _db import _SessionLocal
from _models import ProductionUser, GlobalIdentity
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import get_authenticated_user


async def _handle(token):
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:    return 401, {"detail": error}
        if user.role.value != "admin": return 403, {"detail": "Admin access required."}

        result = await db.execute(
            select(ProductionUser, GlobalIdentity)
            .join(GlobalIdentity, ProductionUser.identity_id == GlobalIdentity.identity_id)
            .where(ProductionUser.is_flagged_as_attacker == True)  # noqa
        )
        rows = result.all()
        return 200, {
            "flagged_users": [
                {
                    "id":                    u.identity_id,
                    "username":              u.username,
                    "email":                 u.email,
                    "role":                  u.role.value,
                    "failed_login_count":    u.failed_login_count,
                    "last_login_ip":         u.last_login_ip,
                    "risk_score":            gi.risk_score,
                    "is_flagged_as_attacker":u.is_flagged_as_attacker,
                }
                for u, gi in rows
            ]
        }


def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    status, data = asyncio.run(_handle(get_bearer_token(request)))
    return {"statusCode": status, "headers": cors_headers("GET, OPTIONS"), "body": json.dumps(data)}
