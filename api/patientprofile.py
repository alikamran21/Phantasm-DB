import asyncio
from _shared import *

async def _run(token, ip, ua):
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        trap = await honeypot_gate(db, user, ip, ua, "PATIENT_VIEW_PROFILE", "/api/patientprofile")
        if trap: return 200, SHADOW_PATIENT_SELF
        r   = await db.execute(select(Patient).where(Patient.identity_id == user.identity_id))
        pat = r.scalar_one_or_none()
        meds = []
        if pat and pat.medications:
            try:    meds = json.loads(pat.medications)
            except: meds = [pat.medications]
        return 200, {
            "id":               user.identity_id,
            "mrn":              pat.mrn if pat else None,
            "full_name":        f"{pat.first_name or ''} {pat.last_name or ''}".strip() if pat else user.username,
            "dob":              pat.dob.isoformat() if (pat and pat.dob) else None,
            "diagnosis":        pat.diagnosis if pat else None,
            "medications":      meds,
            "next_appointment": pat.next_appointment.isoformat() if (pat and pat.next_appointment) else None,
            "email":            user.email,
            "role":             user.role.value,
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    ip = get_client_ip(request)
    ua = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(get_token(request), ip, ua))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
