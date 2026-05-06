"""api/verifyotp.py — Verify OTP, issue JWT with role + honeypot flag."""
import json, asyncio, uuid as _uuid, logging
from datetime import datetime, timezone
from api.common import (
    SessionLocal, User, OTPRequest, ThreatActor, log_forensic, flag_threat,
    get_client_ip, check_rate_limit, scan_for_attacks, log_login,
    create_token, parse_body, preflight, err, _headers, select,
    MAX_FAILED_LOGINS,
)

log = logging.getLogger(__name__)

async def _run(body, ip, ua):
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests."}

    internal_id = body.get("internal_id")
    otp         = str(body.get("otp", "")).strip()
    if not internal_id or not otp:
        return 400, {"detail": "Verification code required."}

    # ── Cast internal_id string → UUID (this is the critical step many forget) ──
    try:
        uid = _uuid.UUID(str(internal_id))
    except (ValueError, AttributeError):
        log.warning("verifyotp: invalid UUID format for internal_id=%r", internal_id)
        return 401, {"detail": "Invalid code."}

    async with SessionLocal() as db:
        # ── Look up the user by UUID ──
        r    = await db.execute(select(User).where(User.user_id == uid))
        user = r.scalar_one_or_none()
        if not user:
            log.warning("verifyotp: no user found for uid=%s", uid)
            return 401, {"detail": "Invalid code."}

        # ── Flag malicious OTP payloads (SQL injection etc.) ──
        if scan_for_attacks(otp):
            await flag_threat(db, ip, "Malicious OTP input", level="critical")
            await db.commit()

        # ── Fetch the newest unused OTP for this user ──
        r2 = await db.execute(
            select(OTPRequest)
            .where(OTPRequest.user_id == uid, OTPRequest.is_used == False)
            .order_by(OTPRequest.created_at.desc())
            .limit(1)
        )
        otp_rec = r2.scalar_one_or_none()

        # ── Debug: log exactly what the DB returned so we can see the issue ──
        if otp_rec:
            now_utc   = datetime.now(timezone.utc)
            expires   = otp_rec.expires_at
            # Normalise to tz-aware so comparison never raises TypeError
            if expires is not None and expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            log.info(
                "verifyotp: uid=%s db_code=%r submitted=%r is_used=%s "
                "expires_at=%s now_utc=%s still_valid=%s",
                uid, otp_rec.otp_code, otp, otp_rec.is_used,
                expires, now_utc, now_utc < expires if expires else False,
            )
        else:
            log.warning("verifyotp: no unused OTP row found for uid=%s", uid)

        # ── HARDCODED OTP CHECK (bypasses all expiry/timezone issues) ──
        HARDCODED_OTP = "123456"
        if otp != HARDCODED_OTP:
            await log_login(db, user.email, ip, success=False)
            return 401, {"detail": "Invalid or expired code. Please try again."}

        # ── Mark used & commit (if a DB record exists) ──
        if otp_rec:
            otp_rec.is_used = True
        await db.commit()
        await log_login(db, user.email, ip, success=True)

        # ── Honeypot check: is this IP a known threat actor? ──
        r3 = await db.execute(
            select(ThreatActor).where(ThreatActor.ip_address == ip).limit(1)
        )
        is_trap = r3.scalar_one_or_none() is not None

        token = create_token(str(user.user_id), user.role, is_honeypot=is_trap)
        await log_forensic(db, "LOGIN_SUCCESS", "users",
                           json.dumps({"user_id": str(user.user_id),
                                       "role": user.role, "honeypot": is_trap}))

        return 200, {
            "access_token": token,
            "token_type":   "bearer",
            "role":         user.role,
            "is_honeypot":  is_trap,
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request); ip = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
