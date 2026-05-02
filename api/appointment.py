import asyncio
from _shared import *

async def _run(token, body, ip, ua):
    datetime_str = str(body.get("datetime_str", "")).strip()
    reason       = str(body.get("reason", "Patient requested"))
    if not datetime_str:
        return 400, {"detail": "datetime_str is required."}
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        await honeypot_gate(db, user, ip, ua, "PATIENT_SCHEDULE_APPT", "/api/appointment",
                            payload=json.dumps({"datetime": datetime_str, "reason": reason}))
        return 200, {"detail": "Appointment scheduled.", "datetime": datetime_str}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    ip   = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(get_token(request), body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
