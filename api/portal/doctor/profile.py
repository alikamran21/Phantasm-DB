# api/portal/doctor/profile.py
"""GET /api/portal/doctor/profile — returns doctor profile (real or shadow)."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from _db import _SessionLocal
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import SHADOW_DOCTOR_PROFILE, get_authenticated_user, honeypot_gate


async def _handle(token: str, ip: str, user_agent: str) -> tuple[int, dict]:
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}

        is_trap = await honeypot_gate(
            db, user, ip, user_agent,
            action="DOCTOR_VIEW_PROFILE",
            endpoint="/api/portal/doctor/profile",
        )

        if is_trap:
            return 200, SHADOW_DOCTOR_PROFILE

        return 200, {
            "id":        user.id,
            "npi":       user.npi,
            "full_name": user.full_name,
            "email":     user.email,
            "role":      user.role.value,
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
