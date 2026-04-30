# backend/app/security.py
"""
Active-defense security middleware for Phantasm-DB.

Responsibilities:
  1. Inspect every incoming request for known attack signatures.
  2. Apply per-IP rate limiting (sliding window, in-memory).
  3. Flag users / IPs in the database when thresholds are exceeded.
  4. Provide helper utilities used by routing.py and auth.py.

Detection categories:
  - SQL Injection patterns
  - Cross-Site Scripting (XSS) signatures
  - Path traversal sequences
  - Command injection characters
  - Rapid request bursts (rate limiting)
"""

import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditLog, User

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (from environment with sensible defaults)
# ---------------------------------------------------------------------------
RATE_LIMIT_MAX      = int(os.environ.get("RATE_LIMIT_REQUESTS", 30))
RATE_LIMIT_WINDOW   = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))
MAX_FAILED_LOGINS   = int(os.environ.get("MAX_FAILED_LOGINS", 5))
LOG_PAYLOADS        = os.environ.get("HONEYPOT_LOG_PAYLOADS", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Attack Signature Patterns
# ---------------------------------------------------------------------------
_SQLI_PATTERNS = [
    r"(--|;|\/\*|\*\/)",                         # SQL comment / terminator sequences
    r"\b(union\s+select|select\s+.*\s+from)\b",  # UNION-based extraction
    r"\b(drop|alter|truncate|exec|execute)\b",   # DDL / DML keywords
    r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", # Blind time-based SQLi
    r"(1\s*=\s*1|1\s*=\s*'1'|'\s*or\s*'1)",     # Always-true conditions
    r"(xp_cmdshell|information_schema|sysobjects)", # MSSQL / info-schema probes
]

_XSS_PATTERNS = [
    r"<\s*script[\s>]",                          # <script> tags
    r"javascript\s*:",                           # javascript: URI
    r"on\w+\s*=\s*['\"]",                        # onerror=, onclick=, etc.
    r"<\s*iframe",                               # iframe injections
    r"document\s*\.\s*cookie",                  # Cookie theft
    r"eval\s*\(",                                # eval() calls
]

_PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",                                    # Unix path traversal
    r"\.\.\\",                                   # Windows path traversal
    r"%2e%2e[%2f%5c]",                          # URL-encoded traversal
    r"etc/passwd",                               # Classic LFI target
    r"(windows|winnt)[/\\]system32",            # Windows system paths
]

_COMMAND_INJECTION_PATTERNS = [
    r"[;&|`]\s*(ls|dir|cat|type|whoami|id|uname|net\s+user|wget|curl|bash|sh|cmd)",
    r"\$\([^)]+\)",                              # $(command) substitution
    r"`[^`]+`",                                  # Backtick execution
]

# Compile all patterns for efficiency
_ALL_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    ("SQL_INJECTION",       [re.compile(p, re.IGNORECASE) for p in _SQLI_PATTERNS]),
    ("XSS",                 [re.compile(p, re.IGNORECASE) for p in _XSS_PATTERNS]),
    ("PATH_TRAVERSAL",      [re.compile(p, re.IGNORECASE) for p in _PATH_TRAVERSAL_PATTERNS]),
    ("COMMAND_INJECTION",   [re.compile(p, re.IGNORECASE) for p in _COMMAND_INJECTION_PATTERNS]),
]

# ---------------------------------------------------------------------------
# In-memory rate limiter (sliding window)
# Structure: { ip: deque([timestamp, ...]) }
# ---------------------------------------------------------------------------
_rate_store: dict[str, deque] = defaultdict(deque)


def _get_client_ip(request: Request) -> str:
    """
    Extract the real client IP, respecting common reverse-proxy headers.
    Prefer X-Forwarded-For when behind Nginx.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(ip: str) -> bool:
    """
    Sliding-window rate limiter.
    Returns True if the request is WITHIN limits, False if it exceeds them.
    """
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW
    dq = _rate_store[ip]

    # Evict timestamps outside the current window
    while dq and dq[0] < window_start:
        dq.popleft()

    if len(dq) >= RATE_LIMIT_MAX:
        return False   # Rate limit exceeded

    dq.append(now)
    return True


def scan_for_attacks(text: str) -> Optional[tuple[str, str]]:
    """
    Scan a string for known attack signatures.

    Returns (category, matched_snippet) if an attack is found,
    or None if the string is clean.
    """
    if not text:
        return None
    for category, patterns in _ALL_PATTERNS:
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                return category, m.group(0)[:120]   # Cap snippet length
    return None


async def inspect_request(
    request: Request,
    db: AsyncSession,
    user_id: Optional[int] = None,
) -> Optional[tuple[str, str]]:
    """
    Full request inspection pipeline.

    1. Check rate limit for the client IP.
    2. Scan URL path + query string + body for attack patterns.
    3. If a threat is detected:
       a. Set is_flagged_as_attacker = True on the user (if known).
       b. Write an AuditLog entry.
       c. Return the detection reason.

    Returns (category, reason_string) if malicious, else None.
    """
    ip = _get_client_ip(request)

    # --- Step 1: Rate limiting ---
    if not check_rate_limit(ip):
        reason = "RATE_LIMIT_EXCEEDED"
        await _flag_and_log(db, request, ip, user_id, reason, "Rate limit exceeded", payload=None)
        return "RATE_LIMIT", reason

    # --- Step 2: Build the corpus to inspect ---
    # URL path + query
    corpus_parts = [str(request.url.path), str(request.url.query)]

    # Request body (best-effort; may be empty for GETs)
    body_text: Optional[str] = None
    try:
        raw_body = await request.body()
        if raw_body:
            body_text = raw_body.decode("utf-8", errors="replace")
            corpus_parts.append(body_text)
    except Exception:
        pass   # Body unavailable — continue without it

    full_corpus = " ".join(corpus_parts)

    # --- Step 3: Pattern matching ---
    result = scan_for_attacks(full_corpus)
    if result:
        category, snippet = result
        reason = f"{category}: matched '{snippet}'"
        payload_to_log = body_text if LOG_PAYLOADS else "[REDACTED]"
        await _flag_and_log(db, request, ip, user_id, category, reason, payload_to_log)
        return category, reason

    return None


async def _flag_and_log(
    db: AsyncSession,
    request: Request,
    ip: str,
    user_id: Optional[int],
    action: str,
    detection_reason: str,
    payload: Optional[str],
) -> None:
    """
    Internal: write an AuditLog entry and flag the user in the database.
    """
    try:
        # Write audit log
        log_entry = AuditLog(
            ip_address       = ip,
            user_agent       = request.headers.get("User-Agent", "")[:512],
            user_id          = user_id,
            action           = f"ATTACK_DETECTED:{action}",
            endpoint         = str(request.url.path),
            http_method      = request.method,
            payload          = payload,
            is_malicious     = True,
            is_honeypot_action = False,
            detection_reason = detection_reason,
        )
        db.add(log_entry)

        # Flag the user if we have an identity
        if user_id:
            await db.execute(
                update(User)
                .where(User.id == user_id)
                .values(is_flagged_as_attacker=True)
            )

        await db.commit()
        log.warning("ATTACK DETECTED | ip=%s user_id=%s reason=%s", ip, user_id, detection_reason)

    except Exception as exc:
        log.error("Failed to persist attack log: %s", exc)
        await db.rollback()


async def write_audit_log(
    db: AsyncSession,
    request: Request,
    action: str,
    user_id: Optional[int] = None,
    response_status: int = 200,
    payload: Optional[str] = None,
    is_honeypot: bool = False,
    is_malicious: bool = False,
    detection_reason: Optional[str] = None,
) -> None:
    """
    Public helper for writing a standard (non-attack) audit log entry.
    Called by routing.py and auth.py for every significant action.
    """
    ip = _get_client_ip(request)
    try:
        entry = AuditLog(
            ip_address        = ip,
            user_agent        = request.headers.get("User-Agent", "")[:512],
            user_id           = user_id,
            action            = action,
            endpoint          = str(request.url.path),
            http_method       = request.method,
            payload           = payload,
            response_status   = response_status,
            is_malicious      = is_malicious,
            is_honeypot_action= is_honeypot,
            detection_reason  = detection_reason,
        )
        db.add(entry)
        await db.commit()
    except Exception as exc:
        log.error("Failed to write audit log: %s", exc)
        await db.rollback()


async def increment_failed_login(db: AsyncSession, user: User) -> bool:
    """
    Increment failed login counter. Returns True if user should now be flagged.
    """
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_FAILED_LOGINS:
        user.is_flagged_as_attacker = True
        log.warning("User %s flagged after %d failed logins.", user.email, user.failed_login_count)
    await db.commit()
    return user.is_flagged_as_attacker
