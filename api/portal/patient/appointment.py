# api/portal/patient/appointment.py
"""POST /api/portal/patient/appointment — schedule appointment (real or silently discard)."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from _db import _SessionLocal
from _handler_base import client_ip, cors_headers, err, get_bearer_token, parse_body, preflight
from _portal_base import get_authenticated_user, honeypot_gate


async def _handle(token: str, body: dict, ip: str, user_agent: str) -> tuple[int, dict]:
    datetime_str = str(body.get("datetime_str", "")).strip()
    reason       = str(body.get("reason", "Patient requested")).strip()

    if not datetime_str:
        return 400, {"detail": "datetime_str is required."}

    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}

        is_trap = await honeypot_gate(
            db, user, ip, user_agent,
            action="PATIENT_SCHEDULE_APPT",
            endpoint="/api/portal/patient/appointment",
            payload=json.dumps({"datetime": datetime_str, "reason": reason}),
        )

        # Both real and honeypot return success — honeypot just doesn't persist
        return 200, {"detail": "Appointment scheduled successfully.", "datetime": datetime_str}


def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight()
    if request.method != "POST":
        return err("Method not allowed.", 405)

    token      = get_bearer_token(request)
    body       = parse_body(request)
    ip         = client_ip(request)
    user_agent = (request.headers or {}).get("user-agent", "")

    status, data = asyncio.run(_handle(token, body, ip, user_agent))
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps(data)}
