# api/_auth_utils.py
import os as _os, sys as _sys
# Add lib/ to path — works both locally and in Vercel (/var/task/lib)
for _candidate in [
    _os.path.dirname(_os.path.abspath(__file__)),          # local: lib/ itself
    '/var/task/lib',                                        # Vercel production
    _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'lib'),  # fallback
]:
    if _os.path.isdir(_candidate) and _candidate not in _sys.path:
        _sys.path.insert(0, _candidate)

"""
JWT issuance / verification and bcrypt password helpers.
Shared across all Vercel serverless API functions.
"""
import os
import random
import string
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

JWT_SECRET    = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE    = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd.verify(plain, hashed)


def create_access_token(subject: int, role: str, is_honeypot: bool = False) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE)
    return jwt.encode(
        {"sub": str(subject), "role": role, "honeypot": is_honeypot,
         "exp": expire, "iat": datetime.now(timezone.utc)},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )


def decode_token(token: str) -> dict:
    """Raises ValueError on invalid/expired token."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise ValueError("Invalid or expired token") from e


def generate_otp() -> str:
    return "".join(random.SystemRandom().choices(string.digits, k=6))
