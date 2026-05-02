import asyncio
from _shared import *

async def _run(token, body, ip, ua):
    note_text  = str(body.get("note_text", "")).strip()
    patient_id = body.get("patient_id", 0)
    if not note_text:
        return 400, {"detail": "Note text is required."}
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        await honeypot_gate(db, user, ip, ua, "DOCTOR_SUBMIT_NOTE", "/api/notes",
                            payload=json.dumps({"patient_id": patient_id, "len": len(note_text)}))
        return 200, {"detail": "Note saved successfully."}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    ip   = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(get_token(request), body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
