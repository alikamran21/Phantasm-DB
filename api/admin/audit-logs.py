# api/admin/audit-logs.py
"""GET /api/admin/audit-logs — Admin only."""
import asyncio, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select
from _db import _SessionLocal
from _models import ForensicLedger
from _handler_base import client_ip, cors_headers, err, get_bearer_token, preflight
from _portal_base import get_authenticated_user


async def _handle(token, skip, limit):
    async with _SessionLocal() as db:
        user, error = await get_authenticated_user(token, db)
        if error:    return 401, {"detail": error}
        if user.role.value != "admin": return 403, {"detail": "Admin access required."}

        result = await db.execute(
            select(ForensicLedger).order_by(ForensicLedger.timestamp.desc()).offset(skip).limit(limit)
        )
        logs = result.scalars().all()
        return 200, {
            "total": len(logs),
            "logs": [
                {
                    "id":               l.log_id,
                    "timestamp":        l.timestamp.isoformat() if l.timestamp else None,
                    "ip_address":       l.identity.ip_address if l.identity else "unknown",
                    "user_id":          l.user_id,
                    "action":           l.action,
                    "endpoint":         l.endpoint,
                    "http_method":      l.http_method,
                    "raw_query":        l.raw_query,
                    "is_malicious":     l.is_malicious,
                    "is_honeypot_action": l.was_deceived,
                    "detection_reason": l.detection_reason,
                    "response_status":  l.response_status,
                    "duration_ms":      l.duration_ms,
                }
                for l in logs
            ],
        }


def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "GET":     return err("Method not allowed.", 405)
    query = getattr(request, "query", {}) or {}
    skip  = int(query.get("skip", 0))
    limit = min(int(query.get("limit", 100)), 500)
    status, data = asyncio.run(_handle(get_bearer_token(request), skip, limit))
    return {"statusCode": status, "headers": cors_headers("GET, OPTIONS"), "body": json.dumps(data)}
