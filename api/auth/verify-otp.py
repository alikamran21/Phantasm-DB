# api/auth/verify-otp.py
"""
POST /api/auth/verify-otp
Step 2 of 2FA — validate OTP, issue JWT with honeypot flag if attacker.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select

from _db import _SessionLocal
from _models import OTPRequest, User
from _auth_utils import create_access_token
from _handler_base import client_ip, cors_headers, err, ok, parse_body, preflight
from _security import check_rate_limit, scan_for_attacks, write_audit_log


async def _handle(body: dict, ip: str, user_agent: str) -> tuple[int, dict]:
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests."}

    email = str(body.get("email", "")).strip().lower()
    otp   = str(body.get("otp",   "")).strip()

    if not email or not otp:
        return 400, {"detail": "Email and OTP are required."}

    # Scan OTP field for injection attempts
    attack = scan_for_attacks(otp)

    async with _SessionLocal() as db:
        result = await db.execute(select(User).where(User.email == email))
        user: User | None = result.scalar_one_or_none()

        if not user:
            return 401, {"detail": "Invalid OTP."}

        if attack:
            category, snippet = attack
            user.is_flagged_as_attacker = True
            await db.commit()
            await write_audit_log(
                db, ip, f"ATTACK_DETECTED:{category}", "/api/auth/verify-otp",
                method="POST", user_agent=user_agent,
                user_id=user.id, payload=otp[:80],
                is_malicious=True,
                detection_reason=f"{category}: '{snippet}'",
            )

        # Find latest unused, unexpired OTP
        otp_result = await db.execute(
            select(OTPRequest)
            .where(OTPRequest.user_id == user.id, OTPRequest.is_used == False)  # noqa: E712
            .order_by(OTPRequest.created_at.desc())
            .limit(1)
        )
        otp_rec: OTPRequest | None = otp_result.scalar_one_or_none()

        if not otp_rec or not otp_rec.is_valid() or otp_rec.otp_code != otp:
            await write_audit_log(
                db, ip, "OTP_FAIL", "/api/auth/verify-otp",
                method="POST", user_agent=user_agent,
                user_id=user.id, response_status=401,
            )
            return 401, {"detail": "Invalid or expired OTP."}

        # Mark OTP consumed
        otp_rec.is_used = True
        await db.commit()

        is_honeypot = user.is_flagged_as_attacker
        token       = create_access_token(user.id, user.role.value, is_honeypot=is_honeypot)

        await write_audit_log(
            db, ip, "LOGIN_SUCCESS", "/api/auth/verify-otp",
            method="POST", user_agent=user_agent,
            user_id=user.id, response_status=200,
            is_honeypot=is_honeypot,
        )

        return 200, {
            "access_token": token,
            "token_type":   "bearer",
            "role":         user.role.value,
            "is_honeypot":  is_honeypot,
        }


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
