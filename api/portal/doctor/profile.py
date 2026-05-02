# api/portal/doctor/profile.py

import os as _os, sys as _sys
_lib = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', '..', 'lib')
for _p in [_lib, '/var/task/lib']:
    if _os.path.isdir(_p) and _p not in _sys.path:
        _sys.path.insert(0, _p)

"""GET /api/portal/doctor/profile"""
import asyncio, json, os, sys

from sqlalchemy import select
from _db import _SessionLocal
from _models import Doctor
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import SHADOW_DOCTOR_PROFILE, get_authenticated_user, honeypot_gate


async def _handle(token, ip, ua):
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}
        is_trap = await honeypot_gate(db, user, ip, ua, "DOCTOR_VIEW_PROFILE", "/api/portal/doctor/profile")
        if is_trap:
            return 200, SHADOW_DOCTOR_PROFILE
        doc_result = await db.execute(select(Doctor).where(Doctor.identity_id == user.identity_id))
        doc = doc_result.scalar_one_or_none()
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
    status, data = asyncio.run(_handle(get_bearer_token(request), client_ip(request), (request.headers or {}).get("user-agent","")))
    return {"statusCode": status, "headers": cors_headers("GET, OPTIONS"), "body": json.dumps(data)}
