# api/auth/login.py
"""
POST /api/auth/login
Step 1 of 2FA — validate email + password, dispatch OTP.

Vercel Python serverless function.
Handler signature: handler(request, context) -> Response dict
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone

# Make shared api/ modules importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select

from _db import _SessionLocal
from _models import OTPRequest, User
from _auth_utils import generate_otp, verify_password
from _handler_base import client_ip, cors_headers, err, ok, parse_body, preflight
from _mailer import send_otp_email
from _security import (
    check_rate_limit,
    increment_failed_login,
    scan_for_attacks,
    write_audit_log,
)

OTP_EXPIRE = int(os.environ.get("OTP_EXPIRE_MINUTES", 5))


async def _handle(body: dict, ip: str, user_agent: str) -> tuple[int, dict]:
    # Rate limit
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests. Please wait before trying again."}

    email    = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    if not email or not password:
        return 400, {"detail": "Email and password are required."}

    # Scan inputs for attack signatures
    attack = scan_for_attacks(f"{email} {password}")

    async with _SessionLocal() as db:
        result = await db.execute(select(User).where(User.email == email))
        user: User | None = result.scalar_one_or_none()

        # Log any attack — but never block (silent honeypot approach)
        if attack:
            category, snippet = attack
            if user:
                user.is_flagged_as_attacker = True
                await db.commit()
            await write_audit_log(
                db, ip, f"ATTACK_DETECTED:{category}", "/api/auth/login",
                method="POST", user_agent=user_agent,
                user_id=user.id if user else None,
                payload=f"{email[:80]}",
                is_malicious=True,
                detection_reason=f"{category}: '{snippet}'",
            )

        # Verify credentials
        if not user or not verify_password(password, user.password_hash):
            if user:
                await increment_failed_login(db, user)
            await write_audit_log(
                db, ip, "LOGIN_FAIL", "/api/auth/login",
                method="POST", user_agent=user_agent,
                user_id=user.id if user else None,
                response_status=401,
            )
            return 401, {"detail": "Invalid credentials."}

        # Reset fail counter on success
        user.failed_login_count = 0
        await db.commit()

        # Create OTP record
        otp_code = generate_otp()
        expires  = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE)
        db.add(OTPRequest(
            user_id    = user.id,
            otp_code   = otp_code,
            expires_at = expires,
            created_ip = ip,
        ))
        await db.commit()

        # Send OTP via SMTP
        try:
            send_otp_email(user.email, otp_code, user.full_name or "")
        except Exception as e:
            return 503, {"detail": f"Email delivery failed: {e}"}

        await write_audit_log(
            db, ip, "LOGIN_OTP_SENT", "/api/auth/login",
            method="POST", user_agent=user_agent,
            user_id=user.id, response_status=200,
        )

        return 200, {"detail": "OTP dispatched. Check your email.", "email": user.email}


def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight()
    if request.method != "POST":
        return err("Method not allowed.", 405)

    body       = parse_body(request)
    ip         = client_ip(request)
    user_agent = (request.headers or {}).get("user-agent", "")

    status, data = asyncio.run(_handle(body, ip, user_agent))
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps(data)}
