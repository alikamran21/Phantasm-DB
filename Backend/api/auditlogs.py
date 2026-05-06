"""api/auditlogs.py — Admin: forensic ledger + security alerts."""
import json, asyncio
from api.common import (
    SessionLocal, ForensicLedger, SecurityAlert, ThreatActor,
    get_user, get_token, err, _headers, select, decode_token,
)

async def _run(token, kind, skip, limit):
    if not token: return 401, {"detail": "Not authenticated."}
    try: decode_token(token)
    except: return 401, {"detail": "Invalid token."}
    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        if user.role != "admin": return 403, {"detail": "Admin only."}

        if kind == "alerts":
            rows  = await db.execute(select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).offset(skip).limit(limit))
            items = rows.scalars().all()
            return 200, {"alerts": [{"id": a.alert_id, "title": a.alert_title,
                                      "description": a.description, "resolved": a.is_resolved,
                                      "created_at": a.created_at.isoformat() if a.created_at else None} for a in items]}

        if kind == "threats":
            rows  = await db.execute(select(ThreatActor).order_by(ThreatActor.flagged_at.desc()).offset(skip).limit(limit))
            items = rows.scalars().all()
            return 200, {"threats": [{"id": t.threat_id, "ip": str(t.ip_address) if t.ip_address else None,
                                       "reason": t.reason, "level": t.threat_level,
                                       "flagged_at": t.flagged_at.isoformat() if t.flagged_at else None} for t in items]}
                    # Default: forensic ledger
        rows  = await db.execute(select(ForensicLedger).order_by(ForensicLedger.created_at.desc()).offset(skip).limit(limit))
        items = rows.scalars().all()
        return 200, {"logs": [{"id": l.ledger_id, "action": l.action_type, "table": l.target_table,
                                "payload": l.query_text, "created_at": l.created_at.isoformat() if l.created_at else None}
                               for l in items]}

def handler(request, context=None):
    if request.method == "OPTIONS": return {"statusCode": 204, "headers": _headers("GET, OPTIONS"), "body": ""}
    if request.method != "GET":     return err("Method not allowed.", 405, "GET, OPTIONS")
    args  = getattr(request, "args", {}) or {}
    kind  = args.get("kind", "logs")
    skip  = int(args.get("skip", 0))
    limit = min(int(args.get("limit", 100)), 500)
    status, data = asyncio.run(_run(get_token(request), kind, skip, limit))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}

