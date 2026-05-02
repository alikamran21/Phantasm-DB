import asyncio
from _shared import *

async def _run(token, ip, ua):
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}

        trap = await honeypot_gate(db, user, ip, ua, "DOCTOR_VIEW_PATIENTS", "/api/patients")
        if trap: return 200, {"patients": SHADOW_PATIENTS}

        result = await db.execute(
            select(Patient, ProductionUser)
            .join(ProductionUser, Patient.identity_id == ProductionUser.identity_id)
            .where(ProductionUser.is_active == True)  # noqa
        )
        rows = result.all()
        patients = []
        for p, pu in rows:
            meds = []
            if p.medications:
                try:    meds = json.loads(p.medications)
                except: meds = [p.medications]
            patients.append({
                "id":               p.identity_id,
                "mrn":              p.mrn,
                "full_name":        f"{p.first_name or ''} {p.last_name or ''}".strip() or pu.username,
                "diagnosis":        p.diagnosis,
                "medications":      meds,
                "notes":            p.clinical_notes,
                "next_appointment": p.next_appointment.isoformat() if p.next_appointment else None,
            })
        return 200, {"patients": patients}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    token = get_token(request)
    ip    = get_client_ip(request)
    ua    = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(token, ip, ua))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
