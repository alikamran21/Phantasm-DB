# api/portal/doctor/patients.py
"""GET /api/portal/doctor/patients — returns patient list (real or shadow)."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from sqlalchemy import select

from _db import _SessionLocal
from _models import User, UserRole
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import SHADOW_PATIENTS, get_authenticated_user, honeypot_gate


async def _handle(token: str, ip: str, user_agent: str) -> tuple[int, dict]:
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}

        is_trap = await honeypot_gate(
            db, user, ip, user_agent,
            action="DOCTOR_VIEW_PATIENT_LIST",
            endpoint="/api/portal/doctor/patients",
        )

        if is_trap:
            return 200, {"patients": SHADOW_PATIENTS}

        # Real data — query all active patients
        result   = await db.execute(
            select(User).where(User.role == UserRole.patient, User.is_active == True)  # noqa
        )
        patients = result.scalars().all()
        return 200, {
            "patients": [
                {"id": p.id, "mrn": p.mrn, "full_name": p.full_name, "email": p.email}
                for p in patients
            ]
        }


def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight()
    if request.method != "GET":
        return err("Method not allowed.", 405)

    token      = get_bearer_token(request)
    ip         = client_ip(request)
    user_agent = (request.headers or {}).get("user-agent", "")

    status, data = asyncio.run(_handle(token, ip, user_agent))
    return {"statusCode": status, "headers": cors_headers("GET, OPTIONS"), "body": json.dumps(data)}
