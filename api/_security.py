# api/_security.py
"""
Attack detection, rate limiting, and forensic logging helpers.
Aligned to the full ERD: writes to forensic_ledger, not old audit_logs.

ForensicLedger fields used:
  log_id, raw_query, duration_ms, was_deceived,
  identity_id, timestamp, action, endpoint, http_method,
  response_status, user_agent, is_malicious, detection_reason, user_id
"""
import logging
import os
import re
import time
from collections import defaultdict, deque
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

RATE_LIMIT_MAX    = int(os.environ.get("RATE_LIMIT_REQUESTS",       30))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))
MAX_FAILED_LOGINS = int(os.environ.get("MAX_FAILED_LOGINS",          5))

# ---------------------------------------------------------------------------
# Attack signature patterns  (mirrors ERD Detection_Policies.regex_pattern)
# ---------------------------------------------------------------------------
_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    ("SQL_INJECTION", [
        re.compile(r"(--|;|\/\*|\*\/)",                              re.I),
        re.compile(r"\b(union\s+select|select\s+.*\s+from)\b",      re.I),
        re.compile(r"\b(drop|alter|truncate|exec|execute)\b",       re.I),
        re.compile(r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",  re.I),
        re.compile(r"(1\s*=\s*1|'\s*or\s*'1)",                     re.I),
    ]),
    ("XSS", [
        re.compile(r"<\s*script[\s>]",   re.I),
        re.compile(r"javascript\s*:",    re.I),
        re.compile(r"on\w+\s*=\s*['\"]", re.I),
    ]),
    ("PATH_TRAVERSAL", [
        re.compile(r"\.\./" ),
        re.compile(r"etc/passwd"),
    ]),
    ("COMMAND_INJECTION", [
        re.compile(r"[;&|`]\s*(ls|cat|whoami|bash|sh|curl|wget)", re.I),
    ]),
]

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
    method: str           = "POST",
    user_agent: str       = "",
    user_id: Optional[int] = None,
    payload: Optional[str] = None,       # stored in raw_query
    response_status: int  = 200,
    is_honeypot: bool     = False,        # stored in was_deceived
    is_malicious: bool    = False,
    detection_reason: Optional[str] = None,
) -> None:
    """
    Write a ForensicLedger row.

    Maps legacy parameter names to ERD field names:
      payload      → raw_query
      is_honeypot  → was_deceived
    """
    # Import here to avoid circular import at module load
    from _models import ForensicLedger, GlobalIdentity

    try:
        # Every log entry needs a GlobalIdentity row (total participation)
        # Use existing one for this IP, or create a stub
        from sqlalchemy import select
        gi_result = await db.execute(
            select(GlobalIdentity).where(GlobalIdentity.ip_address == ip).limit(1)
        )
        gi = gi_result.scalar_one_or_none()
        if not gi:
            gi = GlobalIdentity(
                ip_address = ip,
                risk_score = 10.0 if is_malicious else 0.0,
            )
            db.add(gi)
            await db.flush()   # get identity_id without full commit

        entry = ForensicLedger(
            identity_id      = gi.identity_id,
            user_id          = user_id,
            action           = action,
            endpoint         = endpoint,
            http_method      = method,
            raw_query        = payload,
            response_status  = response_status,
            user_agent       = (user_agent or "")[:512],
            is_malicious     = is_malicious,
            was_deceived     = is_honeypot,
            detection_reason = detection_reason,
        )
        db.add(entry)
        await db.commit()

        # If malicious, bump risk_score on the GlobalIdentity
        if is_malicious:
            gi.risk_score = min((gi.risk_score or 0.0) + 10.0, 100.0)
            await db.commit()

    except Exception as exc:
        log.error("write_audit_log failed: %s", exc)
        try:
            await db.rollback()
        except Exception:
            pass


async def increment_failed_login(db: AsyncSession, user) -> bool:
    """Increment failed login counter. Returns True if user is now flagged."""
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_FAILED_LOGINS:
        user.is_flagged_as_attacker = True
    await db.commit()
    return user.is_flagged_as_attacker
