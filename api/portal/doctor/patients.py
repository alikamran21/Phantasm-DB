# api/portal/doctor/patients.py
import os as _os, sys as _sys
_lib = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', '..', 'lib')
if _lib not in _sys.path:
    _sys.path.insert(0, _lib)

"""GET /api/portal/doctor/patients"""
import asyncio, json, os, sys

from sqlalchemy import select
from _db import _SessionLocal
from _models import Patient, ProductionUser, UserRole, Doctor
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import SHADOW_PATIENTS, get_authenticated_user, honeypot_gate


async def _handle(token, ip, ua):
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}

        is_trap = await honeypot_gate(db, user, ip, ua,
            "DOCTOR_VIEW_PATIENT_LIST", "/api/portal/doctor/patients")

        if is_trap:
            return 200, {"patients": SHADOW_PATIENTS}

        # Fetch real patients joined to their ProductionUser
        result = await db.execute(
            select(Patient, ProductionUser)
            .join(ProductionUser, Patient.identity_id == ProductionUser.identity_id)
            .where(ProductionUser.is_active == True)  # noqa
        )
        rows = result.all()
        return 200, {
            "patients": [
                {
                    "id":        p.identity_id,
                    "mrn":       p.mrn,
                    "full_name": f"{p.first_name or ''} {p.last_name or ''}".strip() or pu.username,
                    "diagnosis": p.diagnosis,
                    "next_appointment": p.next_appointment.isoformat() if p.next_appointment else None,
                    "medications": p.medications or [],
                    "notes":     p.clinical_notes,
                }
                for p, pu in rows
            ]
        }


def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    status, data = asyncio.run(_handle(get_bearer_token(request), client_ip(request), (request.headers or {}).get("user-agent","")))
    return {"statusCode": status, "headers": cors_headers("GET, OPTIONS"), "body": json.dumps(data)}
