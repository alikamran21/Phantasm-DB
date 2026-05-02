import asyncio
from _shared import *

async def _run(body, ip, ua):
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests."}
    email    = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not email or not password:
        return 400, {"detail": "Email and password are required."}

    attack = scan_for_attacks(f"{email} {password}")

    async with _SessionLocal() as db:
        r    = await db.execute(select(ProductionUser).where(ProductionUser.email == email))
        user = r.scalar_one_or_none()

        if attack:
            category, snippet = attack
            if user:
                user.is_flagged_as_attacker = True
                await db.commit()
            await write_log(db, ip, f"ATTACK:{category}", "/api/login", user_agent=ua,
                           user_id=user.identity_id if user else None,
                           payload=email[:80], is_malicious=True)

        if not user or not verify_password(password, user.password_hash):
            if user: await increment_failed_login(db, user)
            await write_log(db, ip, "LOGIN_FAIL", "/api/login", user_agent=ua,
                           user_id=user.identity_id if user else None, status=401)
            return 401, {"detail": "Invalid credentials."}

        user.failed_login_count = 0
        await db.commit()

        otp_code = generate_otp()
        db.add(OTPRequest(
            user_id=user.identity_id, otp_code=otp_code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE),
            created_ip=ip,
        ))
        await db.commit()

        try:
            send_otp_email(user.email, otp_code, user.username or "")
        except Exception as e:
            return 503, {"detail": f"Email failed: {e}"}

        return 200, {"detail": "OTP sent.", "internal_id": user.identity_id}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    ip   = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
