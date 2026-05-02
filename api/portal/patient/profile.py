# api/portal/patient/profile.py
import os as _os, sys as _sys
_lib = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', '..', 'lib')
if _lib not in _sys.path:
    _sys.path.insert(0, _lib)

"""GET /api/portal/patient/profile"""
import asyncio, json, os, sys

from sqlalchemy import select
from _db import _SessionLocal
from _models import Patient
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import SHADOW_PATIENT_SELF, get_authenticated_user, honeypot_gate


async def _handle(token, ip, ua):
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}
        is_trap = await honeypot_gate(db, user, ip, ua, "PATIENT_VIEW_PROFILE", "/api/portal/patient/profile")
        if is_trap:
            return 200, SHADOW_PATIENT_SELF
        pat_result = await db.execute(select(Patient).where(Patient.identity_id == user.identity_id))
        pat = pat_result.scalar_one_or_none()
        return 200, {
            "id":               user.identity_id,
            "mrn":              pat.mrn if pat else None,
            "full_name":        f"{pat.first_name or ''} {pat.last_name or ''}".strip() if pat else user.username,
            "dob":              pat.dob.isoformat() if (pat and pat.dob) else None,
            "age":              pat.age if pat else None,
            "diagnosis":        pat.diagnosis if pat else None,
            "next_appointment": pat.next_appointment.isoformat() if (pat and pat.next_appointment) else None,
            "medications":      pat.medications if pat else [],
            "email":            user.email,
            "role":             user.role.value,
        }


def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    status, data = asyncio.run(_handle(get_bearer_token(request), client_ip(request), (request.headers or {}).get("user-agent","")))
    return {"statusCode": status, "headers": cors_headers("GET, OPTIONS"), "body": json.dumps(data)}
