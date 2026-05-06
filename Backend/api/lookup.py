"""api/lookup.py — ID-based OTP login (doctor_id / mrn). Tier 2 Controller."""
import json, asyncio
from datetime import datetime, timedelta, timezone
from api.common import (
    SessionLocal, User, Doctor, Patient, OTPRequest,
    get_client_ip, check_rate_limit, scan_for_attacks,
    generate_otp, send_otp_email, mask_email, log_forensic, flag_threat,
    parse_body, preflight, err, _headers, select, OTP_EXPIRE, log,
)

async def _run(body, ip, ua):
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests. Please wait."}

    raw_id    = str(body.get("user_id", "")).strip()
    role_hint = str(body.get("role", "")).strip().lower()
    if not raw_id:
        return 400, {"detail": "Please enter your ID."}

    attack = scan_for_attacks(raw_id)

    async with SessionLocal() as db:
        user = None

        # Look up by role hint or try both
        if role_hint == "doctor":
            r   = await db.execute(select(Doctor).where(Doctor.doc_id == raw_id))
            doc = r.scalar_one_or_none()
            if doc:
                r2   = await db.execute(select(User).where(User.user_id == doc.user_id))
                user = r2.scalar_one_or_none()
        elif role_hint == "patient":
            r   = await db.execute(select(Patient).where(Patient.mrn == raw_id))
            pat = r.scalar_one_or_none()
            if pat:
                r2   = await db.execute(select(User).where(User.user_id == pat.user_id))
                user = r2.scalar_one_or_none()
        else:
            # Try doctor first, then patient
            r = await db.execute(select(Doctor).where(Doctor.doc_id == raw_id))
            doc = r.scalar_one_or_none()
            if doc:
                r2 = await db.execute(select(User).where(User.user_id == doc.user_id))
                user = r2.scalar_one_or_none()
            if not user:
                r = await db.execute(select(Patient).where(Patient.mrn == raw_id))
                pat = r.scalar_one_or_none()
                if pat:
                    r2 = await db.execute(select(User).where(User.user_id == pat.user_id))
                    user = r2.scalar_one_or_none()

        # Flag attack attempts (isolated commit so it never blocks login)
        if attack:
            try:
                category, snippet = attack
                tid = await flag_threat(db, ip, f"{category}: {snippet}", level="high")
                await log_forensic(db, f"ATTACK:{category}", "lookup", raw_id[:80], threat_id=tid)
                await db.commit()
            except Exception as e:
                log.error("attack logging failed: %s", e)
                await db.rollback()

        if not user or not user.is_active:
            return 401, {"detail": "Invalid ID. Please check and try again."}

        # Insert OTP record
        otp_code = generate_otp()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE)
        try:
            db.add(OTPRequest(
                user_id=user.user_id, otp_code=otp_code,
                expires_at=expires_at,
                created_ip=ip,
            ))
            await db.commit()
        except Exception as e:
            log.error("OTP insert failed: %s", e)
            await db.rollback()
            return 500, {"detail": "Internal error. Please try again."}

        # Send email
        try:
            send_otp_email(user.email, otp_code, user.email.split("@")[0])
        except Exception as e:
            log.error("Email send failed: %s", e)
            return 503, {"detail": f"Could not send verification email: {e}"}

        return 200, {
            "detail":       "Verification code sent to your registered email.",
            "masked_email": mask_email(user.email),
            "internal_id":  str(user.user_id),
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request); ip = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = asyncio.run(_run(body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
