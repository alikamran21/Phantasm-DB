import asyncio
from _shared import *

async def _run(token, body, ip, ua):
    target_id = body.get("user_id")
    if not target_id: return 400, {"detail": "user_id is required."}
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error:                      return 401, {"detail": error}
        if user.role.value != "admin": return 403, {"detail": "Admin only."}
        r      = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == int(target_id)))
        target = r.scalar_one_or_none()
        if not target: return 404, {"detail": "User not found."}
        target.is_flagged_as_attacker = False
        target.failed_login_count     = 0
        await db.commit()
        await write_log(db, ip, f"ADMIN_UNFLAG:{target_id}", "/api/unflaguser",
                       user_agent=ua, user_id=user.identity_id)
        return 200, {"detail": f"User {target_id} unflagged."}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    ip   = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(get_token(request), body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
