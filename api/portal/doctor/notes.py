# api/portal/doctor/notes.py

import os as _os, sys as _sys
_lib = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', '..', 'lib')
for _p in [_lib, '/var/task/lib']:
    if _os.path.isdir(_p) and _p not in _sys.path:
        _sys.path.insert(0, _p)

"""POST /api/portal/doctor/notes"""
import asyncio, json, os, sys

from _db import _SessionLocal
from _handler_base import client_ip, cors_headers, err, get_bearer_token, parse_body, preflight
from _portal_base import get_authenticated_user, honeypot_gate


async def _handle(token, body, ip, ua):
    note_text  = str(body.get("note_text", "")).strip()
    patient_id = body.get("patient_id", 0)
    if not note_text:
        return 400, {"detail": "Note text is required."}
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:
            return 401, {"detail": error}
        is_trap = await honeypot_gate(db, user, ip, ua, "DOCTOR_SUBMIT_NOTE",
            "/api/portal/doctor/notes",
            payload=json.dumps({"patient_id": patient_id, "note_len": len(note_text)}))
        if is_trap:
            return 200, {"detail": "Note saved successfully."}
        return 200, {"detail": "Note saved successfully."}


def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    status, data = asyncio.run(_handle(get_bearer_token(request), body, client_ip(request), (request.headers or {}).get("user-agent","")))
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps(data)}
