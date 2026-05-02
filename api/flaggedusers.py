import asyncio
from _shared import *

async def _run(token):
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error:                      return 401, {"detail": error}
        if user.role.value != "admin": return 403, {"detail": "Admin only."}
        r      = await db.execute(
            select(ProductionUser).where(ProductionUser.is_flagged_as_attacker == True)  # noqa
        )
        flagged = r.scalars().all()
        return 200, {"flagged_users": [
            {"id": u.identity_id, "username": u.username, "email": u.email,
             "role": u.role.value, "failed_login_count": u.failed_login_count,
             "last_login_ip": u.last_login_ip}
            for u in flagged
        ]}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    status, data = asyncio.run(_run(get_token(request)))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
