import asyncio
from _shared import *

async def _run(body, ip, ua):
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests."}
    internal_id = body.get("internal_id")
    otp         = str(body.get("otp", "")).strip()
    if not internal_id or not otp:
        return 400, {"detail": "Verification code is required."}

    async with _SessionLocal() as db:
        r    = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == int(internal_id)))
        user = r.scalar_one_or_none()
        if not user:
            return 401, {"detail": "Invalid code."}

        attack = scan_for_attacks(otp)
        if attack:
            user.is_flagged_as_attacker = True
            await db.commit()

        r2     = await db.execute(
            select(OTPRequest)
            .where(OTPRequest.user_id == user.identity_id, OTPRequest.is_used == False)  # noqa
            .order_by(OTPRequest.created_at.desc()).limit(1)
        )
        otp_rec = r2.scalar_one_or_none()

        if not otp_rec or not otp_rec.is_valid() or otp_rec.otp_code != otp:
            await write_log(db, ip, "OTP_FAIL", "/api/verifyotp", user_agent=ua,
                           user_id=user.identity_id, status=401)
            return 401, {"detail": "Invalid or expired code. Please try again."}

        otp_rec.is_used = True
        await db.commit()

        is_trap = user.is_flagged_as_attacker
        token   = create_token(user.identity_id, user.role.value, is_honeypot=is_trap)

        await write_log(db, ip, "LOGIN_SUCCESS", "/api/verifyotp", user_agent=ua,
                       user_id=user.identity_id, status=200, is_honeypot=is_trap)

        return 200, {"access_token": token, "token_type": "bearer",
                     "role": user.role.value, "is_honeypot": is_trap}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    ip   = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
