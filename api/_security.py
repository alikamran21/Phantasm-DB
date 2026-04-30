# api/_security.py
"""
Attack detection, rate limiting, and audit logging helpers.
Shared across all Vercel serverless API functions.
"""
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from _models import AuditLog, User

log = logging.getLogger(__name__)

RATE_LIMIT_MAX    = int(os.environ.get("RATE_LIMIT_REQUESTS", 30))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))
MAX_FAILED_LOGINS = int(os.environ.get("MAX_FAILED_LOGINS", 5))
LOG_PAYLOADS      = os.environ.get("HONEYPOT_LOG_PAYLOADS", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Attack patterns
# ---------------------------------------------------------------------------
_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    ("SQL_INJECTION", [
        re.compile(r"(--|;|\/\*|\*\/)", re.I),
        re.compile(r"\b(union\s+select|select\s+.*\s+from)\b", re.I),
        re.compile(r"\b(drop|alter|truncate|exec|execute)\b", re.I),
        re.compile(r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", re.I),
        re.compile(r"(1\s*=\s*1|'\s*or\s*'1)", re.I),
    ]),
    ("XSS", [
        re.compile(r"<\s*script[\s>]", re.I),
        re.compile(r"javascript\s*:", re.I),
        re.compile(r"on\w+\s*=\s*['\"]", re.I),
    ]),
    ("PATH_TRAVERSAL", [
        re.compile(r"\.\./"),
        re.compile(r"etc/passwd"),
    ]),
    ("COMMAND_INJECTION", [
        re.compile(r"[;&|`]\s*(ls|cat|whoami|bash|sh|curl|wget)", re.I),
    ]),
]

# In-memory rate store (per Vercel instance — good enough for burst protection)
_rate_store: dict[str, deque] = defaultdict(deque)


def get_client_ip(request_headers: dict, remote_addr: str = "unknown") -> str:
    xff = request_headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() if xff else remote_addr


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


def scan_for_attacks(text: str) -> Optional[tuple[str, str]]:
    if not text:
        return None
    for category, patterns in _PATTERNS:
        for p in patterns:
            m = p.search(text)
            if m:
                return category, m.group(0)[:120]
    return None


async def write_audit_log(
    db: AsyncSession,
    ip: str,
    action: str,
    endpoint: str,
    method: str = "POST",
    user_agent: str = "",
    user_id: Optional[int] = None,
    payload: Optional[str] = None,
    response_status: int = 200,
    is_honeypot: bool = False,
    is_malicious: bool = False,
    detection_reason: Optional[str] = None,
) -> None:
    try:
        entry = AuditLog(
            ip_address        = ip,
            user_agent        = user_agent[:512],
            user_id           = user_id,
            action            = action,
            endpoint          = endpoint,
            http_method       = method,
            payload           = payload,
            response_status   = response_status,
            is_malicious      = is_malicious,
            is_honeypot_action= is_honeypot,
            detection_reason  = detection_reason,
        )
        db.add(entry)
        await db.commit()
    except Exception as e:
        log.error("audit log failed: %s", e)
        await db.rollback()


async def flag_user(db: AsyncSession, user: User) -> None:
    user.is_flagged_as_attacker = True
    await db.commit()


async def increment_failed_login(db: AsyncSession, user: User) -> bool:
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_FAILED_LOGINS:
        user.is_flagged_as_attacker = True
    await db.commit()
    return user.is_flagged_as_attacker
