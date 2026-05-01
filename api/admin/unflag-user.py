# api/admin/unflag-user.py
"""POST /api/admin/unflag-user — Admin only."""
import asyncio, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select
from _db import _SessionLocal
from _models import ProductionUser, GlobalIdentity
from _handler_base import client_ip, cors_headers, err, get_bearer_token, parse_body, preflight
from _portal_base import get_authenticated_user
from _security import write_audit_log


async def _handle(token, body, ip, ua):
    target_id = body.get("user_id")
    if not target_id:
        return 400, {"detail": "user_id is required."}

    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:    return 401, {"detail": error}
        if user.role.value != "admin": return 403, {"detail": "Admin access required."}

        result = await db.execute(
            select(ProductionUser).where(ProductionUser.identity_id == int(target_id))
        )
        target = result.scalar_one_or_none()
        if not target:
            return 404, {"detail": f"User {target_id} not found."}

        target.is_flagged_as_attacker = False
        target.failed_login_count     = 0

        # Reset risk_score on the GlobalIdentity too
        gi_result = await db.execute(
            select(GlobalIdentity).where(GlobalIdentity.identity_id == int(target_id))
        )
        gi = gi_result.scalar_one_or_none()
        if gi:
            gi.risk_score = 0.0

        await db.commit()
        await write_audit_log(db, ip, f"ADMIN_UNFLAG_USER:{target_id}", "/api/admin/unflag-user",
            method="POST", user_agent=ua, user_id=user.identity_id)

        return 200, {"detail": f"User {target_id} ({target.email}) unflagged."}


def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    ip   = client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_handle(get_bearer_token(request), body, ip, ua))
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps(data)}
