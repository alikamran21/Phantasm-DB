# api/auth/verify-otp.py
"""POST /api/auth/verify-otp — validates OTP, issues JWT."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select

from _db import _SessionLocal
from _models import OTPRequest, ProductionUser
from _auth_utils import create_access_token
from _handler_base import client_ip, cors_headers, err, parse_body, preflight
from _security import check_rate_limit, scan_for_attacks, write_audit_log


async def _handle(body: dict, ip: str, user_agent: str) -> tuple[int, dict]:
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests. Please wait before trying again."}

    internal_id = body.get("internal_id")
    otp         = str(body.get("otp", "")).strip()

    if not internal_id or not otp:
        return 400, {"detail": "Verification code is required."}

    attack = scan_for_attacks(otp)

    async with _SessionLocal() as db:
        result = await db.execute(
            select(ProductionUser).where(ProductionUser.identity_id == int(internal_id))
        )
        user = result.scalar_one_or_none()

        if not user:
            return 401, {"detail": "Invalid verification code."}

        if attack:
            category, snippet = attack
            user.is_flagged_as_attacker = True
            await db.commit()
            await write_audit_log(
                db, ip, f"ATTACK_DETECTED:{category}", "/api/auth/verify-otp",
                method="POST", user_agent=user_agent,
                user_id=user.identity_id, payload=otp[:80],
                is_malicious=True,
                detection_reason=f"{category}: '{snippet}'",
            )

        otp_result = await db.execute(
            select(OTPRequest)
            .where(OTPRequest.user_id == user.identity_id, OTPRequest.is_used == False)  # noqa
            .order_by(OTPRequest.created_at.desc())
            .limit(1)
        )
        otp_rec = otp_result.scalar_one_or_none()

        if not otp_rec or not otp_rec.is_valid() or otp_rec.otp_code != otp:
            await write_audit_log(
                db, ip, "OTP_FAIL", "/api/auth/verify-otp",
                method="POST", user_agent=user_agent,
                user_id=user.identity_id, response_status=401,
            )
            return 401, {"detail": "Invalid or expired verification code. Please try again."}

        otp_rec.is_used = True
        await db.commit()

        is_honeypot = user.is_flagged_as_attacker
        token       = create_access_token(user.identity_id, user.role.value, is_honeypot=is_honeypot)

        await write_audit_log(
            db, ip, "LOGIN_SUCCESS", "/api/auth/verify-otp",
            method="POST", user_agent=user_agent,
            user_id=user.identity_id, response_status=200,
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
