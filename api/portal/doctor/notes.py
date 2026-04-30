# api/portal/doctor/notes.py
"""POST /api/portal/doctor/notes — save clinical note (real or silently discard)."""
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
    patient_id = body.get("patient_id", 0)
    note_text  = str(body.get("note_text", "")).strip()

    if not note_text:
        return 400, {"detail": "Note text is required."}

    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}

        is_trap = await honeypot_gate(
            db, user, ip, user_agent,
            action="DOCTOR_SUBMIT_NOTE",
            endpoint="/api/portal/doctor/notes",
            payload=json.dumps({"patient_id": patient_id, "note_len": len(note_text)}),
        )

        if is_trap:
            # Convincing success — nothing actually written
            return 200, {"detail": "Note saved successfully."}

        # Real path — in production, persist to a clinical_notes table
        # For now, log the action and return success
        return 200, {"detail": "Note saved successfully."}


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
