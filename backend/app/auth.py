# backend/app/auth.py
"""
Authentication module for Phantasm-DB.

Covers:
  - Password hashing / verification (bcrypt via passlib)
  - JWT access-token issuance and validation
  - OTP generation, email dispatch (SMTP), and verification
  - Login endpoint logic with honeypot awareness
"""

import logging
import os
import random
import smtplib
import string
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_db
from .models import OTPRequest, User, UserRole
from .security import increment_failed_login, inspect_request, write_audit_log

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
JWT_SECRET      = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM   = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINS = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))
OTP_EXPIRE_MINS = int(os.environ.get("OTP_EXPIRE_MINUTES", 5))

SMTP_HOST        = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT        = int(os.environ.get("SMTP_PORT", 587))
SMTP_USE_TLS     = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USERNAME    = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD    = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_NAME   = os.environ.get("SMTP_FROM_NAME", "Serenity Psychiatric Care")
SMTP_FROM_EMAIL  = os.environ.get("SMTP_FROM_EMAIL", "no-reply@example.com")

# ---------------------------------------------------------------------------
# Password hashing (bcrypt, 12 rounds)
# ---------------------------------------------------------------------------
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(subject: int, role: str, is_honeypot: bool = False) -> str:
    """
    Issue a signed JWT.
    `is_honeypot` is embedded so the backend can enforce honeypot routing
    even on subsequent requests without a DB hit.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINS)
    payload = {
        "sub": str(subject),
        "role": role,
        "honeypot": is_honeypot,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Verify and decode a JWT. Raises HTTPException 401 on any failure.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ---------------------------------------------------------------------------
# JWT Bearer dependency
# ---------------------------------------------------------------------------
_bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency that returns the authenticated User or raises 401.
    Refreshes the is_flagged_as_attacker status from DB on each request.
    """
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    payload = decode_access_token(credentials.credentials)
    user_id = int(payload["sub"])

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    return user


# ---------------------------------------------------------------------------
# OTP utilities
# ---------------------------------------------------------------------------

def _generate_otp() -> str:
    """Generate a cryptographically random 6-digit OTP."""
    return "".join(random.SystemRandom().choices(string.digits, k=6))


def _send_otp_email(recipient_email: str, otp: str, full_name: str = "") -> None:
    """
    Dispatch the OTP via SMTP.
    Raises RuntimeError on delivery failure so the caller can handle it.
    """
    greeting = f"Dear {full_name}," if full_name else "Hello,"

    html_body = f"""
    <html><body style="font-family: 'Inter', Arial, sans-serif; background: #f8fafc; margin:0; padding:0;">
      <div style="max-width:480px; margin:40px auto; background:#fff; border-radius:16px;
                  border:1px solid #e2e8f0; overflow:hidden; box-shadow:0 4px 24px rgba(0,0,0,.06);">
        <div style="background:#0f766e; padding:32px; text-align:center;">
          <h1 style="color:#fff; margin:0; font-size:22px; letter-spacing:-0.5px;">
            🌿 Serenity Psychiatric Care
          </h1>
          <p style="color:#99f6e4; margin:8px 0 0; font-size:13px;">Secure Clinical Portal</p>
        </div>
        <div style="padding:32px;">
          <p style="color:#334155; margin:0 0 16px;">{greeting}</p>
          <p style="color:#475569; font-size:14px; line-height:1.6;">
            Your one-time verification code is:
          </p>
          <div style="background:#f0fdf4; border:2px solid #86efac; border-radius:12px;
                      padding:20px; text-align:center; margin:20px 0;">
            <span style="font-size:40px; font-weight:700; letter-spacing:12px; color:#15803d;
                         font-family:'Courier New', monospace;">{otp}</span>
          </div>
          <p style="color:#94a3b8; font-size:12px;">
            This code expires in <strong>{OTP_EXPIRE_MINS} minutes</strong>.<br>
            If you did not request this code, please contact your system administrator immediately.
          </p>
        </div>
        <div style="background:#f8fafc; padding:16px 32px; text-align:center;
                    border-top:1px solid #e2e8f0;">
          <p style="color:#cbd5e1; font-size:11px; margin:0;">
            This is an automated message. Do not reply. |
            HIPAA-compliant communications.
          </p>
        </div>
      </div>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Serenity Portal Verification Code"
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"]      = recipient_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM_EMAIL, [recipient_email], msg.as_string())
        log.info("OTP dispatched to %s", recipient_email)
    except Exception as exc:
        log.error("SMTP dispatch failed: %s", exc)
        raise RuntimeError(f"Email delivery failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email:    EmailStr
    password: str

class OTPRequest_(BaseModel):   # Renamed to avoid clash with ORM model
    email: EmailStr
    otp:   str

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    role:         str
    is_honeypot:  bool = False


# ---------------------------------------------------------------------------
# Auth router
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=dict)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Step 1 of 2FA: validate email + password, then dispatch OTP.

    Attack behaviour:
      - SQL injection / XSS in the request body → flag user, still proceed
        (attacker is silently let through — honeypot takes over later).
      - Too many failed attempts → flag user.
    """
    # Inspect for attacks — do NOT block; silently log and flag
    await inspect_request(request, db, user_id=None)

    # Look up user
    result = await db.execute(select(User).where(User.email == body.email))
    user: Optional[User] = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        if user:
            flagged = await increment_failed_login(db, user)
            log.warning("Failed login for %s (flagged=%s)", body.email, flagged)
        await write_audit_log(
            db, request, "LOGIN_FAIL",
            user_id=user.id if user else None,
            response_status=401,
            payload=f"email={body.email}",
        )
        # Generic error — do not reveal whether email exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    # Credentials valid — reset failed counter
    user.failed_login_count = 0
    await db.commit()

    # Generate and store OTP
    otp_code = _generate_otp()
    expires   = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINS)
    otp_record = OTPRequest(
        user_id    = user.id,
        otp_code   = otp_code,
        expires_at = expires,
        created_ip = request.client.host if request.client else None,
    )
    db.add(otp_record)
    await db.commit()

    # Dispatch OTP email — if delivery fails, surface a 503
    try:
        _send_otp_email(user.email, otp_code, user.full_name or "")
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    await write_audit_log(db, request, "LOGIN_OTP_SENT", user_id=user.id)

    return {"detail": "OTP dispatched. Please check your email.", "email": user.email}


@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(
    body: OTPRequest_,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Step 2 of 2FA: verify the OTP and issue a JWT.

    The JWT embeds `honeypot=True` if the user is flagged as an attacker,
    so routing.py can enforce shadow-environment redirection.
    """
    await inspect_request(request, db, user_id=None)

    # Find user
    result = await db.execute(select(User).where(User.email == body.email))
    user: Optional[User] = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid OTP.")

    # Find latest unused OTP for this user
    otp_result = await db.execute(
        select(OTPRequest)
        .where(OTPRequest.user_id == user.id, OTPRequest.is_used == False)  # noqa: E712
        .order_by(OTPRequest.created_at.desc())
        .limit(1)
    )
    otp_record: Optional[OTPRequest] = otp_result.scalar_one_or_none()

    if not otp_record or not otp_record.is_valid() or otp_record.otp_code != body.otp:
        await write_audit_log(db, request, "OTP_FAIL", user_id=user.id, response_status=401)
        raise HTTPException(status_code=401, detail="Invalid or expired OTP.")

    # Mark OTP as consumed
    otp_record.is_used = True
    await db.commit()

    is_honeypot = user.is_flagged_as_attacker
    token = create_access_token(user.id, user.role.value, is_honeypot=is_honeypot)

    await write_audit_log(
        db, request, "LOGIN_SUCCESS",
        user_id=user.id,
        is_honeypot=is_honeypot,
    )

    if is_honeypot:
        log.warning("HONEYPOT TOKEN issued to flagged user %s (%s)", user.email, user.id)

    return TokenResponse(
        access_token=token,
        role=user.role.value,
        is_honeypot=is_honeypot,
    )
