# api/auth/lookup.py
"""
POST /api/auth/lookup
Step 1 — Doctor/Patient ID-based login.
Looks up by license_no (Doctor) or mrn (Patient), sends OTP to email on file.
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from _db import _SessionLocal
from _models import Doctor, OTPRequest, Patient, ProductionUser
from _auth_utils import generate_otp
from _handler_base import client_ip, cors_headers, err, parse_body, preflight
from _mailer import send_otp_email
from _security import check_rate_limit, scan_for_attacks, write_audit_log

OTP_EXPIRE = int(os.environ.get("OTP_EXPIRE_MINUTES", 5))


def _mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            masked_local = local[0] + "*"
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"
    except Exception:
        return "****@****.***"


async def _handle(body: dict, ip: str, user_agent: str) -> tuple[int, dict]:
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests. Please wait before trying again."}

    raw_id    = str(body.get("user_id", "")).strip()
    role_hint = str(body.get("role", "")).strip().lower()

    if not raw_id:
        return 400, {"detail": "Please enter your ID."}

    attack = scan_for_attacks(raw_id)

    async with _SessionLocal() as db:
        user: ProductionUser | None = None

        if role_hint == "doctor":
            # Look up Doctor by license_no, join to ProductionUser
            doc_result = await db.execute(
                select(Doctor).where(Doctor.license_no == raw_id)
            )
            doc = doc_result.scalar_one_or_none()
            if doc:
                pu_result = await db.execute(
                    select(ProductionUser).where(
                        ProductionUser.identity_id == doc.identity_id
                    )
                )
                user = pu_result.scalar_one_or_none()

        elif role_hint == "patient":
            # Look up Patient by mrn, join to ProductionUser
            pat_result = await db.execute(
                select(Patient).where(Patient.mrn == raw_id)
            )
            pat = pat_result.scalar_one_or_none()
            if pat:
                pu_result = await db.execute(
                    select(ProductionUser).where(
                        ProductionUser.identity_id == pat.identity_id
                    )
                )
                user = pu_result.scalar_one_or_none()

        else:
            # No role hint — try both
            doc_result = await db.execute(
                select(Doctor).where(Doctor.license_no == raw_id)
            )
            doc = doc_result.scalar_one_or_none()
            if doc:
                pu_result = await db.execute(
                    select(ProductionUser).where(
                        ProductionUser.identity_id == doc.identity_id
                    )
                )
                user = pu_result.scalar_one_or_none()

            if not user:
                pat_result = await db.execute(
                    select(Patient).where(Patient.mrn == raw_id)
                )
                pat = pat_result.scalar_one_or_none()
                if pat:
                    pu_result = await db.execute(
                        select(ProductionUser).where(
                            ProductionUser.identity_id == pat.identity_id
                        )
                    )
                    user = pu_result.scalar_one_or_none()

        # Log attack silently
        if attack:
            category, snippet = attack
            if user:
                user.is_flagged_as_attacker = True
                await db.commit()
            await write_audit_log(
                db, ip, f"ATTACK_DETECTED:{category}", "/api/auth/lookup",
                method="POST", user_agent=user_agent,
                user_id=user.identity_id if user else None,
                payload=raw_id[:80], is_malicious=True,
                detection_reason=f"{category}: '{snippet}'",
            )

        if not user or not user.is_active:
            await write_audit_log(
                db, ip, "LOOKUP_FAIL", "/api/auth/lookup",
                method="POST", user_agent=user_agent,
                payload=raw_id[:80], response_status=401,
            )
            return 401, {"detail": "Invalid ID. Please check your credentials and try again."}

        # Generate and store OTP
        otp_code = generate_otp()
        expires  = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE)
        db.add(OTPRequest(
            user_id    = user.identity_id,
            otp_code   = otp_code,
            expires_at = expires,
            created_ip = ip,
        ))
        await db.commit()

        try:
            full_name = f"{user.username}"
            send_otp_email(user.email, otp_code, full_name)
        except Exception as e:
            return 503, {"detail": f"Could not send verification email. Please contact support."}

        await write_audit_log(
            db, ip, "LOOKUP_OTP_SENT", "/api/auth/lookup",
            method="POST", user_agent=user_agent,
            user_id=user.identity_id, response_status=200,
        )

        return 200, {
            "detail":       "Verification code sent.",
            "masked_email": _mask_email(user.email),
            "user_id":      raw_id,
            "internal_id":  user.identity_id,
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
