import asyncio
from _shared import *

async def _run(token, ip, ua):
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        trap = await honeypot_gate(db, user, ip, ua, "DOCTOR_VIEW_PROFILE", "/api/doctorprofile")
        if trap: return 200, SHADOW_DOCTOR
        r   = await db.execute(select(Doctor).where(Doctor.identity_id == user.identity_id))
        doc = r.scalar_one_or_none()
        return 200, {
            "id":            user.identity_id,
            "license_no":    doc.license_no if doc else None,
            "specialization":doc.specialization if doc else None,
            "username":      user.username,
            "email":         user.email,
            "role":          user.role.value,
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    ip = get_client_ip(request)
    ua = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(get_token(request), ip, ua))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
