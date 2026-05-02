import asyncio
from _shared import *

async def _run(token, skip, limit):
    async with _SessionLocal() as db:
        user, error = await get_user(token, db)
        if error:                      return 401, {"detail": error}
        if user.role.value != "admin": return 403, {"detail": "Admin only."}
        r    = await db.execute(
            select(ForensicLedger).order_by(ForensicLedger.timestamp.desc())
            .offset(skip).limit(limit)
        )
        logs = r.scalars().all()
        return 200, {"total": len(logs), "logs": [
            {
                "id":               l.log_id,
                "timestamp":        l.timestamp.isoformat() if l.timestamp else None,
                "user_id":          l.user_id,
                "action":           l.action,
                "endpoint":         l.endpoint,
                "http_method":      l.http_method,
                "is_malicious":     l.is_malicious,
                "is_honeypot_action": l.was_deceived,
                "detection_reason": l.detection_reason,
                "response_status":  l.response_status,
            }
            for l in logs
        ]}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    query = getattr(request, "query", {}) or {}
    skip  = int(query.get("skip", 0))
    limit = min(int(query.get("limit", 100)), 500)
    status, data = asyncio.run(_run(get_token(request), skip, limit))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
