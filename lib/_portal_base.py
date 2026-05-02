# api/_portal_base.py
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
Shared portal guard and honeypot gate for all portal API functions.

ERD alignment:
  - ProductionUser.identity_id  is the PK (not .id)
  - is_flagged_as_attacker lives on ProductionUser
  - ForensicLedger.was_deceived = True for honeypot actions
"""
import os
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from _auth_utils import decode_token
from _models import ProductionUser, ForensicLedger
from _security import write_audit_log

# ---------------------------------------------------------------------------
# Backward-compat alias  (some files still import User)
# ---------------------------------------------------------------------------
User = ProductionUser

# ---------------------------------------------------------------------------
# Synthetic shadow data — shown to trapped attackers (no real PII)
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
    "id": 8001, "license_no": "DOC-SHADOW-01", "full_name": "Dr. Elias Thornton",
    "specialization": "Psychiatry", "patient_count": len(SHADOW_PATIENTS),
}


async def get_authenticated_user(
    token: Optional[str],
    db: AsyncSession,
) -> tuple[Optional[ProductionUser], Optional[str]]:
    """
    Decode JWT → fetch fresh ProductionUser from DB.
    Returns (user, None) on success or (None, error_string).
    """
    if not token:
        return None, "Not authenticated."
    try:
        payload = decode_token(token)
    except ValueError as e:
        return None, str(e)

    user_id = int(payload["sub"])
    result  = await db.execute(
        select(ProductionUser).where(ProductionUser.identity_id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return None, "User not found or inactive."

    return user, None


async def honeypot_gate(
    db: AsyncSession,
    user: ProductionUser,
    ip: str,
    user_agent: str,
    action: str,
    endpoint: str,
    payload: Optional[str] = None,
) -> bool:
    """
    Re-read is_flagged_as_attacker from DB (fresh), log the action,
    return True if this user should be served honeypot content.
    Sets was_deceived=True in ForensicLedger for honeypot actions.
    """
    result     = await db.execute(
        select(ProductionUser).where(ProductionUser.identity_id == user.identity_id)
    )
    fresh_user = result.scalar_one_or_none()
    is_trap    = bool(fresh_user and fresh_user.is_flagged_as_attacker)

    await write_audit_log(
        db, ip, action, endpoint,
        method      = "POST",
        user_agent  = user_agent,
        user_id     = user.identity_id,
        payload     = payload,
        is_honeypot = is_trap,
        is_malicious= is_trap,
    )
    return is_trap
