# api/_portal_base.py
"""
Shared portal guard and honeypot gate used by all portal API functions.

get_authenticated_user() — decodes JWT, re-fetches user from DB
honeypot_gate()          — checks fresh DB flag, logs action, returns bool
"""
import json
import os
import sys
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from _auth_utils import decode_token
from _models import AuditLog, User
from _security import write_audit_log

# ---------------------------------------------------------------------------
# Synthetic shadow data shown to trapped attackers
# All names, MRNs, diagnoses are entirely fabricated.
# ---------------------------------------------------------------------------
SHADOW_PATIENTS = [
    {
        "id": 9001, "mrn": "PT-SHADOW-001", "full_name": "Eleanor Voss",
        "dob": "1987-03-14", "diagnosis": "Generalised Anxiety Disorder (F41.1)",
        "provider": "Dr. Fatima Rehman", "next_appointment": "2025-08-12 10:00",
        "medications": ["Sertraline 50mg", "Lorazepam 0.5mg PRN"],
        "notes": "Patient reports improved sleep. Continue current regimen.",
    },
    {
        "id": 9002, "mrn": "PT-SHADOW-002", "full_name": "Marcus Delray",
        "dob": "1995-11-29", "diagnosis": "Major Depressive Disorder (F32.1)",
        "provider": "Dr. Ali Kamran", "next_appointment": "2025-08-15 14:30",
        "medications": ["Fluoxetine 20mg", "Quetiapine 25mg PRN"],
        "notes": "Discussed CBT strategies. Follow-up in two weeks.",
    },
    {
        "id": 9003, "mrn": "PT-SHADOW-003", "full_name": "Priya Nair",
        "dob": "1979-07-02", "diagnosis": "Bipolar II Disorder (F31.81)",
        "provider": "Dr. Sarah Jenkins", "next_appointment": "2025-08-20 09:00",
        "medications": ["Lamotrigine 100mg", "Aripiprazole 10mg"],
        "notes": "Mood stable. Encouraged mindfulness journaling.",
    },
]

SHADOW_PATIENT_SELF = {
    "id": 9001, "mrn": "PT-SHADOW-001", "full_name": "Eleanor Voss",
    "dob": "1987-03-14", "diagnosis": "Generalised Anxiety Disorder (F41.1)",
    "provider": "Dr. Fatima Rehman", "next_appointment": "2025-08-12 10:00",
    "medications": ["Sertraline 50mg", "Lorazepam 0.5mg PRN"],
}

SHADOW_DOCTOR_PROFILE = {
    "id": 8001, "npi": "DOC-SHADOW-01", "full_name": "Dr. Elias Thornton",
    "specialty": "Psychiatry", "patient_count": len(SHADOW_PATIENTS),
}


async def get_authenticated_user(
    token: Optional[str],
    db: AsyncSession,
) -> tuple[Optional[User], Optional[str]]:
    """
    Decode JWT and return (user, None) on success or (None, error_message).
    Re-fetches from DB so is_flagged_as_attacker is always fresh.
    """
    if not token:
        return None, "Not authenticated."
    try:
        payload = decode_token(token)
    except ValueError as e:
        return None, str(e)

    user_id = int(payload["sub"])
    result  = await db.execute(select(User).where(User.id == user_id))
    user    = result.scalar_one_or_none()

    if not user or not user.is_active:
        return None, "User not found or inactive."

    return user, None


async def honeypot_gate(
    db: AsyncSession,
    user: User,
    ip: str,
    user_agent: str,
    action: str,
    endpoint: str,
    payload: Optional[str] = None,
) -> bool:
    """
    Re-read the attacker flag from DB, log the action, return True if trapped.
    """
    result     = await db.execute(select(User).where(User.id == user.id))
    fresh_user = result.scalar_one_or_none()
    is_trap    = bool(fresh_user and fresh_user.is_flagged_as_attacker)

    await write_audit_log(
        db, ip, action, endpoint,
        method="POST", user_agent=user_agent,
        user_id=user.id, payload=payload,
        is_honeypot=is_trap, is_malicious=is_trap,
    )
    return is_trap
