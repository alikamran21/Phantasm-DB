# api/initdb.py — Vercel Python Serverless Function
# api/health.py
# Auto-generated — fully self-contained Vercel Python function

import enum, json, logging, os, random, re, smtplib, ssl, string, time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# ── Third-party ──────────────────────────────────────────────
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, func, select, or_
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.pool import NullPool

log = logging.getLogger(__name__)

# ============================================================
# CONFIG
# ============================================================
JWT_SECRET    = os.environ.get("JWT_SECRET_KEY", "changeme")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE    = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))
OTP_EXPIRE    = int(os.environ.get("OTP_EXPIRE_MINUTES", 5))

SMTP_HOST       = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", 587))
SMTP_TLS        = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USER       = os.environ.get("SMTP_USERNAME", "")
SMTP_PASS       = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_NAME  = os.environ.get("SMTP_FROM_NAME", "Serenity Psychiatric Care")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", "noreply@example.com")

RATE_LIMIT_MAX    = int(os.environ.get("RATE_LIMIT_REQUESTS", 30))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))
MAX_FAILED_LOGINS = int(os.environ.get("MAX_FAILED_LOGINS", 5))

# ============================================================
# DATABASE
# ============================================================
def _make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx

def _build_db_url():
    raw    = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("DATABASE_URL environment variable is not set")
    parsed = urlparse(raw)
    qp     = parse_qs(parsed.query, keep_blank_values=True)
    ssl_ok = qp.pop("sslmode", ["disable"])[0] in ("require", "verify-ca", "verify-full")
    qp.pop("channel_binding", None)
    url = urlunparse((
        "postgresql+asyncpg",
        parsed.netloc, parsed.path, parsed.params,
        urlencode({k: v[0] for k, v in qp.items()}),
        parsed.fragment,
    ))
    return url, ({"ssl": _make_ssl_ctx()} if ssl_ok else {})

_db_url, _db_connect_args = _build_db_url()

_engine = create_async_engine(
    _db_url, poolclass=NullPool,
    connect_args=_db_connect_args, echo=False,
)
_SessionLocal = async_sessionmaker(
    bind=_engine, class_=AsyncSession,
    expire_on_commit=False, autoflush=False, autocommit=False,
)

# ============================================================
# ORM MODELS
# ============================================================
class Base(DeclarativeBase):
    pass

class UserRole(str, enum.Enum):
    admin   = "admin"
    doctor  = "doctor"
    patient = "patient"

class GlobalIdentity(Base):
    __tablename__ = "global_identities"
    identity_id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address  = Column(String(64), nullable=False, default="unknown")
    mac_address = Column(String(64), nullable=True)
    risk_score  = Column(Integer,    nullable=False, default=0)

class ProductionUser(Base):
    __tablename__ = "production_users"
    identity_id            = Column(Integer, ForeignKey("global_identities.identity_id"), primary_key=True)
    username               = Column(String(255), unique=True, nullable=False)
    email                  = Column(String(255), unique=True, nullable=False)
    password_hash          = Column(String(255), nullable=False, default="")
    role                   = Column(Enum(UserRole), nullable=False, default=UserRole.patient)
    mfa_enabled            = Column(Boolean, default=True)
    is_active              = Column(Boolean, default=True)
    is_flagged_as_attacker = Column(Boolean, default=False, index=True)
    failed_login_count     = Column(Integer,  default=0)
    last_login_ip          = Column(String(64), nullable=True)

class Doctor(Base):
    __tablename__ = "doctors"
    identity_id     = Column(Integer, ForeignKey("production_users.identity_id"), primary_key=True)
    license_no      = Column(String(100), unique=True, nullable=False)
    specialization  = Column(String(255), nullable=True)

class Patient(Base):
    __tablename__ = "patients"
    identity_id         = Column(Integer, ForeignKey("production_users.identity_id"), primary_key=True)
    mrn                 = Column(String(50), unique=True, nullable=False)
    first_name          = Column(String(100), nullable=True)
    last_name           = Column(String(100), nullable=True)
    dob                 = Column(DateTime(timezone=True), nullable=True)
    ssn                 = Column(String(20), nullable=True)
    diagnosis           = Column(String(512), nullable=True)
    clinical_notes      = Column(Text, nullable=True)
    medications         = Column(Text, nullable=True)   # JSON array stored as text
    next_appointment    = Column(DateTime(timezone=True), nullable=True)
    attending_doctor_id = Column(Integer, ForeignKey("doctors.identity_id"), nullable=True)

class OTPRequest(Base):
    __tablename__ = "otp_requests"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_id    = Column(Integer, ForeignKey("production_users.identity_id", ondelete="CASCADE"), nullable=False)
    otp_code   = Column(String(6),  nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used    = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_ip = Column(String(64), nullable=True)

    def is_valid(self):
        return (not self.is_used) and (datetime.now(timezone.utc) < self.expires_at)

class ForensicLedger(Base):
    __tablename__ = "forensic_ledger"
    log_id           = Column(Integer, primary_key=True, autoincrement=True)
    identity_id      = Column(Integer, ForeignKey("global_identities.identity_id"), nullable=True)
    user_id          = Column(Integer, nullable=True)
    timestamp        = Column(DateTime(timezone=True), server_default=func.now())
    action           = Column(String(128), nullable=False)
    endpoint         = Column(String(512), nullable=False)
    http_method      = Column(String(10),  default="POST")
    raw_query        = Column(Text,        nullable=True)
    response_status  = Column(Integer,     nullable=True)
    user_agent       = Column(String(512), nullable=True)
    is_malicious     = Column(Boolean,     default=False)
    was_deceived     = Column(Boolean,     default=False)
    detection_reason = Column(String(512), nullable=True)
    duration_ms      = Column(Integer,     nullable=True)

async def init_db():
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# ============================================================
# SECURITY
# ============================================================
_ATTACK_PATTERNS = [
    ("SQL_INJECTION", [
        re.compile(r"(--|;|\/\*|\*\/)",                         re.I),
        re.compile(r"\b(union\s+select|select\s+.*\s+from)\b", re.I),
        re.compile(r"\b(drop|alter|truncate|exec|execute)\b",  re.I),
        re.compile(r"(1\s*=\s*1|'\s*or\s*'1)",                re.I),
    ]),
    ("XSS", [
        re.compile(r"<\s*script[\s>]", re.I),
        re.compile(r"javascript\s*:",  re.I),
    ]),
    ("PATH_TRAVERSAL", [re.compile(r"\.\./")]),
    ("CMD_INJECTION",  [re.compile(r"[;&|`]\s*(ls|cat|whoami|bash|sh)", re.I)]),
]

_rate_store: dict = defaultdict(deque)

def get_client_ip(request) -> str:
    hdrs = request.headers if hasattr(request, "headers") else {}
    xff  = hdrs.get("x-forwarded-for", hdrs.get("X-Forwarded-For", ""))
    return xff.split(",")[0].strip() if xff else "unknown"

def check_rate_limit(ip: str) -> bool:
    now   = time.monotonic()
    start = now - RATE_LIMIT_WINDOW
    dq    = _rate_store[ip]
    while dq and dq[0] < start:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return False
    dq.append(now)
    return True

def scan_for_attacks(text: str):
    if not text:
        return None
    for category, patterns in _ATTACK_PATTERNS:
        for p in patterns:
            m = p.search(text)
            if m:
                return category, m.group(0)[:80]
    return None

async def write_log(db, ip, action, endpoint, method="POST",
                    user_agent="", user_id=None, payload=None,
                    status=200, is_honeypot=False, is_malicious=False,
                    detection_reason=None):
    try:
        gi_result = await db.execute(
            select(GlobalIdentity).where(GlobalIdentity.ip_address == ip).limit(1)
        )
        gi = gi_result.scalar_one_or_none()
        if not gi:
            gi = GlobalIdentity(ip_address=ip, risk_score=10 if is_malicious else 0)
            db.add(gi)
            await db.flush()

        db.add(ForensicLedger(
            identity_id=gi.identity_id, user_id=user_id,
            action=action, endpoint=endpoint, http_method=method,
            raw_query=payload, response_status=status,
            user_agent=(user_agent or "")[:512],
            is_malicious=is_malicious, was_deceived=is_honeypot,
            detection_reason=detection_reason,
        ))
        await db.commit()
    except Exception as e:
        log.error("write_log failed: %s", e)
        try: await db.rollback()
        except: pass

async def increment_failed_login(db, user):
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_FAILED_LOGINS:
        user.is_flagged_as_attacker = True
    await db.commit()
    return user.is_flagged_as_attacker

# ============================================================
# AUTH
# ============================================================
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

def hash_password(plain: str) -> str:    return _pwd.hash(plain)
def verify_password(plain: str, h: str) -> bool: return _pwd.verify(plain, h)

def create_token(user_id: int, role: str, is_honeypot: bool = False) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "honeypot": is_honeypot,
         "exp": exp, "iat": datetime.now(timezone.utc)},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise ValueError("Invalid or expired token") from e

def generate_otp() -> str:
    return "".join(random.SystemRandom().choices(string.digits, k=6))

def mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
        masked = local[0] + "*" * max(len(local)-2, 1) + (local[-1] if len(local)>2 else "")
        return f"{masked}@{domain}"
    except:
        return "****@****.***"

# ============================================================
# EMAIL
# ============================================================
def send_otp_email(to: str, otp: str, name: str = "") -> None:
    greeting = f"Dear {name}," if name else "Hello,"
    html = f"""<html><body style="font-family:Arial,sans-serif;background:#f8fafc;">
      <div style="max-width:480px;margin:40px auto;background:#fff;border-radius:12px;border:1px solid #e2e8f0;">
        <div style="background:#0f766e;padding:24px;text-align:center;border-radius:12px 12px 0 0;">
          <h1 style="color:#fff;margin:0;font-size:20px;">Serenity Psychiatric Care</h1>
        </div>
        <div style="padding:32px;">
          <p style="color:#334155;">{greeting}</p>
          <p style="color:#475569;">Your verification code:</p>
          <div style="background:#f0fdf4;border:2px solid #86efac;border-radius:8px;padding:16px;text-align:center;margin:16px 0;">
            <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#15803d;font-family:monospace;">{otp}</span>
          </div>
          <p style="color:#94a3b8;font-size:12px;">Expires in {OTP_EXPIRE} minutes.</p>
        </div>
      </div>
    </body></html>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Serenity Portal Verification Code"
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"]      = to
    msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as srv:
        if SMTP_TLS: srv.starttls()
        if SMTP_USER and SMTP_PASS: srv.login(SMTP_USER, SMTP_PASS)
        srv.sendmail(SMTP_FROM_EMAIL, [to], msg.as_string())

# ============================================================
# HTTP HELPERS
# ============================================================
_ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGINS", "*").split(",")[0].strip()

def _headers(methods="POST, OPTIONS"):
    return {
        "Access-Control-Allow-Origin":  _ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": methods,
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Init-Secret",
        "Content-Type": "application/json",
    }

def ok(data, status=200):
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}

def err(detail, status=400):
    return {"statusCode": status, "headers": _headers(), "body": json.dumps({"detail": detail})}

def preflight():
    return {"statusCode": 204, "headers": _headers(), "body": ""}

def parse_body(request):
    try:
        raw = getattr(request, "body", b"") or b""
        if isinstance(raw, str): raw = raw.encode()
        return json.loads(raw) if raw else {}
    except:
        return {}

def get_token(request):
    hdrs = request.headers if hasattr(request, "headers") else {}
    auth = hdrs.get("Authorization", hdrs.get("authorization", ""))
    return auth[7:] if auth.startswith("Bearer ") else None

# ============================================================
# PORTAL HELPERS
# ============================================================
SHADOW_PATIENTS = [
    {"id":9001,"mrn":"PT-SHADOW-001","full_name":"Eleanor Voss","diagnosis":"Generalised Anxiety Disorder (F41.1)",
     "provider":"Dr. Fatima Rehman","next_appointment":"2025-08-12 10:00","medications":["Sertraline 50mg"],"notes":"Stable."},
    {"id":9002,"mrn":"PT-SHADOW-002","full_name":"Marcus Delray","diagnosis":"Major Depressive Disorder (F32.1)",
     "provider":"Dr. Ali Kamran","next_appointment":"2025-08-15 14:30","medications":["Fluoxetine 20mg"],"notes":"Improving."},
    {"id":9003,"mrn":"PT-SHADOW-003","full_name":"Priya Nair","diagnosis":"Bipolar II Disorder (F31.81)",
     "provider":"Dr. Sarah Jenkins","next_appointment":"2025-08-20 09:00","medications":["Lamotrigine 100mg"],"notes":"Stable."},
]
SHADOW_PATIENT_SELF  = SHADOW_PATIENTS[0]
SHADOW_DOCTOR        = {"id":8001,"license_no":"DOC-SHADOW-01","full_name":"Dr. Elias Thornton","specialization":"Psychiatry"}

async def get_user(token, db):
    """Decode JWT → return fresh ProductionUser or (None, error_string)."""
    if not token:
        return None, "Not authenticated."
    try:
        payload = decode_token(token)
    except ValueError as e:
        return None, str(e)
    uid    = int(payload["sub"])
    result = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == uid))
    user   = result.scalar_one_or_none()
    if not user or not user.is_active:
        return None, "User not found."
    return user, None

async def honeypot_gate(db, user, ip, ua, action, endpoint, payload=None):
    """Returns True if user is flagged (serve shadow data)."""
    result = await db.execute(select(ProductionUser).where(ProductionUser.identity_id == user.identity_id))
    fresh  = result.scalar_one_or_none()
    trap   = bool(fresh and fresh.is_flagged_as_attacker)
    await write_log(db, ip, action, endpoint, user_agent=ua,
                    user_id=user.identity_id, payload=payload,
                    is_honeypot=trap, is_malicious=trap)
    return trap


# ============================================================
# HANDLER — Vercel calls this for every request
# ============================================================

import asyncio
INIT_SECRET = os.environ.get("INIT_SECRET", "")

async def _run(secret):
    if INIT_SECRET and secret != INIT_SECRET:
        return 403, {"detail": "Invalid X-Init-Secret."}
    await init_db()
    seeded = False
    admin_email    = os.environ.get("ADMIN_SEED_EMAIL", "")
    admin_password = os.environ.get("ADMIN_SEED_PASSWORD", "")
    if admin_email and admin_password:
        async with _SessionLocal() as db:
            r = await db.execute(select(ProductionUser).where(ProductionUser.role == UserRole.admin).limit(1))
            if not r.scalar_one_or_none():
                gi = GlobalIdentity(ip_address="127.0.0.1", risk_score=0)
                db.add(gi); await db.flush()
                db.add(ProductionUser(
                    identity_id=gi.identity_id, username="admin",
                    email=admin_email, password_hash=hash_password(admin_password),
                    role=UserRole.admin, mfa_enabled=True, is_active=True,
                ))
                await db.commit()
                seeded = True
    return 200, {"detail": "Database initialised.", "tables_created": True, "admin_seeded": seeded}

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    hdrs   = request.headers if hasattr(request, "headers") else {}
    secret = hdrs.get("x-init-secret", hdrs.get("X-Init-Secret", ""))
    status, data = asyncio.run(_run(secret))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
