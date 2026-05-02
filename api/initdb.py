import asyncio
from _shared import *

INIT_SECRET = os.environ.get("INIT_SECRET", "")

async def _run(secret):
    if INIT_SECRET and secret != INIT_SECRET:
        return 403, {"detail": "Invalid X-Init-Secret."}
    await init_db()
    seeded = False
    admin_email    = os.environ.get("ADMIN_SEED_EMAIL", "")
    admin_password = os.environ.get("ADMIN_SEED_PASSWORD", "")
    if admin_email and admin_password:
        async with _SessionLocal() as db:
            r = await db.execute(select(ProductionUser).where(ProductionUser.role == UserRole.admin).limit(1))
            if not r.scalar_one_or_none():
                gi = GlobalIdentity(ip_address="127.0.0.1", risk_score=0)
                db.add(gi); await db.flush()
                db.add(ProductionUser(
                    identity_id=gi.identity_id, username="admin",
                    email=admin_email, password_hash=hash_password(admin_password),
                    role=UserRole.admin, mfa_enabled=True, is_active=True,
                ))
                await db.commit()
                seeded = True
    return 200, {"detail": "Database initialised.", "tables_created": True, "admin_seeded": seeded}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    hdrs   = request.headers if hasattr(request, "headers") else {}
    secret = hdrs.get("x-init-secret", hdrs.get("X-Init-Secret", ""))
    status, data = asyncio.run(_run(secret))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
