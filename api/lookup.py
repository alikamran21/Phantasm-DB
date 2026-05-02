import asyncio
from _shared import *

async def _run(body, ip, ua):
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests. Please wait."}

    raw_id    = str(body.get("user_id", "")).strip()
    role_hint = str(body.get("role", "")).strip().lower()

    if not raw_id:
        return 400, {"detail": "Please enter your ID."}

    attack = scan_for_attacks(raw_id)

    async with _SessionLocal() as db:
        user = None

        if role_hint == "doctor":
            r = await db.execute(select(Doctor).where(Doctor.license_no == raw_id))
            doc = r.scalar_one_or_none()
            if doc:
                r2 = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == doc.identity_id))
                user = r2.scalar_one_or_none()
        elif role_hint == "patient":
            r = await db.execute(select(Patient).where(Patient.mrn == raw_id))
            pat = r.scalar_one_or_none()
            if pat:
                r2 = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == pat.identity_id))
                user = r2.scalar_one_or_none()
        else:
            r = await db.execute(select(Doctor).where(Doctor.license_no == raw_id))
            doc = r.scalar_one_or_none()
            if doc:
                r2 = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == doc.identity_id))
                user = r2.scalar_one_or_none()
            if not user:
                r = await db.execute(select(Patient).where(Patient.mrn == raw_id))
                pat = r.scalar_one_or_none()
                if pat:
                    r2 = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == pat.identity_id))
                    user = r2.scalar_one_or_none()

        if attack:
            category, snippet = attack
            if user:
                user.is_flagged_as_attacker = True
                await db.commit()
            await write_log(db, ip, f"ATTACK:{category}", "/api/lookup",
                           user_agent=ua, user_id=user.identity_id if user else None,
                           payload=raw_id[:80], is_malicious=True,
                           detection_reason=f"{category}: '{snippet}'")

        if not user or not user.is_active:
            await write_log(db, ip, "LOOKUP_FAIL", "/api/lookup", user_agent=ua, status=401)
            return 401, {"detail": "Invalid ID. Please check and try again."}

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
            return 503, {"detail": f"Could not send email: {e}"}

        await write_log(db, ip, "LOOKUP_OTP_SENT", "/api/lookup",
                       user_agent=ua, user_id=user.identity_id, status=200)

        return 200, {
            "detail":       "Verification code sent.",
            "masked_email": mask_email(user.email),
            "internal_id":  user.identity_id,
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request)
    ip   = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
