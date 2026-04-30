# backend/app/routing.py
"""
Honeypot Routing Engine for Phantasm-DB.

This module is the core of the active-defense architecture.

How it works:
  1. Every portal request passes through `honeypot_gate()`.
  2. The gate checks the JWT claim `honeypot=True` OR re-checks the DB flag
     to catch users flagged after token issuance.
  3. Flagged users receive honeypot data (synthetic) instead of real data.
  4. Every honeypot interaction is written to AuditLogs with is_honeypot_action=True.
  5. The attacker sees a pixel-perfect clone of the real interface — they
     never learn they are being observed.

Shadow data:
  - Honeypot patient records are entirely synthetic (no real PII).
  - Any writes (prescriptions, notes, appointments) are silently discarded
    after being logged.
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import get_current_user
from .database import get_db
from .models import AuditLog, User
from .security import inspect_request, write_audit_log

log = logging.getLogger(__name__)

router = APIRouter(tags=["Portal"])

# ---------------------------------------------------------------------------
# Synthetic shadow data — shown to trapped attackers in place of real records.
# All names, MRNs, diagnoses etc. are entirely fabricated.
# ---------------------------------------------------------------------------
_SHADOW_PATIENTS = [
    {
        "id": 9001,
        "mrn": "PT-SHADOW-001",
        "full_name": "Eleanor Voss",
        "dob": "1987-03-14",
        "diagnosis": "Generalised Anxiety Disorder (F41.1)",
        "provider": "Dr. Fatima Rehman",
        "next_appointment": "2025-08-12 10:00",
        "medications": ["Sertraline 50mg", "Lorazepam 0.5mg PRN"],
        "notes": "Patient reports improved sleep. Continue current regimen.",
        "is_shadow": True,
    },
    {
        "id": 9002,
        "mrn": "PT-SHADOW-002",
        "full_name": "Marcus Delray",
        "dob": "1995-11-29",
        "diagnosis": "Major Depressive Disorder (F32.1)",
        "provider": "Dr. Ali Kamran",
        "next_appointment": "2025-08-15 14:30",
        "medications": ["Fluoxetine 20mg", "Quetiapine 25mg PRN"],
        "notes": "Discussed CBT strategies. Follow-up in two weeks.",
        "is_shadow": True,
    },
    {
        "id": 9003,
        "mrn": "PT-SHADOW-003",
        "full_name": "Priya Nair",
        "dob": "1979-07-02",
        "diagnosis": "Bipolar II Disorder (F31.81)",
        "provider": "Dr. Sarah Jenkins",
        "next_appointment": "2025-08-20 09:00",
        "medications": ["Lamotrigine 100mg", "Aripiprazole 10mg"],
        "notes": "Mood stable. Encouraged mindfulness journaling.",
        "is_shadow": True,
    },
]

_SHADOW_DOCTOR_PROFILE = {
    "id": 8001,
    "npi": "DOC-SHADOW-01",
    "full_name": "Dr. Elias Thornton",
    "specialty": "Psychiatry",
    "patient_count": len(_SHADOW_PATIENTS),
    "is_shadow": True,
}

_SHADOW_PATIENT_SELF = {
    "id": 9001,
    "mrn": "PT-SHADOW-001",
    "full_name": "Eleanor Voss",
    "dob": "1987-03-14",
    "diagnosis": "Generalised Anxiety Disorder (F41.1)",
    "provider": "Dr. Fatima Rehman",
    "next_appointment": "2025-08-12 10:00",
    "medications": ["Sertraline 50mg", "Lorazepam 0.5mg PRN"],
    "is_shadow": True,
}


# ---------------------------------------------------------------------------
# Gate helper
# ---------------------------------------------------------------------------

async def honeypot_gate(
    request: Request,
    current_user: User,
    db: AsyncSession,
    action: str,
    payload: Optional[str] = None,
) -> bool:
    """
    Determines whether this user should be served honeypot content.

    Re-reads `is_flagged_as_attacker` from DB (not just the JWT claim)
    so that a flag applied AFTER token issuance takes effect immediately.

    Returns True  → serve honeypot.
    Returns False → serve real data.

    Always writes an audit log entry.
    """
    # Re-fetch fresh flag from DB
    result = await db.execute(select(User).where(User.id == current_user.id))
    fresh: Optional[User] = result.scalar_one_or_none()
    is_attacker = (fresh and fresh.is_flagged_as_attacker) or False

    await write_audit_log(
        db=db,
        request=request,
        action=action,
        user_id=current_user.id,
        payload=payload,
        is_honeypot=is_attacker,
        is_malicious=is_attacker,
    )

    if is_attacker:
        log.warning(
            "HONEYPOT SERVE | user_id=%s ip=%s action=%s",
            current_user.id,
            request.client.host if request.client else "?",
            action,
        )

    return is_attacker


# ---------------------------------------------------------------------------
# Pydantic schemas for write operations
# ---------------------------------------------------------------------------

class WriteNoteBody(BaseModel):
    patient_id: int
    note_text:  str

class ScheduleAppointmentBody(BaseModel):
    patient_id:   int
    datetime_str: str
    reason:       str


# ---------------------------------------------------------------------------
# Doctor Portal Endpoints
# ---------------------------------------------------------------------------

@router.get("/portal/doctor/patients")
async def get_doctor_patients(
    request:      Request,
    current_user: User           = Depends(get_current_user),
    db:           AsyncSession   = Depends(get_db),
):
    """
    Return the patient list for the authenticated doctor.
    Attackers receive the synthetic shadow patient list.
    """
    await inspect_request(request, db, user_id=current_user.id)
    is_trap = await honeypot_gate(request, current_user, db, "DOCTOR_VIEW_PATIENT_LIST")

    if is_trap:
        return {"patients": _SHADOW_PATIENTS, "honeypot": True}

    # Real data path — query actual patients assigned to this doctor
    # (Simplified: return all patients for demo; scope by doctor NPI in production)
    from .models import User as UserModel, UserRole
    result = await db.execute(
        select(UserModel).where(UserModel.role == UserRole.patient, UserModel.is_active == True)  # noqa
    )
    patients = result.scalars().all()
    return {
        "patients": [
            {
                "id":        p.id,
                "mrn":       p.mrn,
                "full_name": p.full_name,
                "email":     p.email,
            }
            for p in patients
        ]
    }


@router.post("/portal/doctor/notes")
async def submit_doctor_note(
    body:         WriteNoteBody,
    request:      Request,
    current_user: User         = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    """
    Submit a clinical note.
    Honeypot users — note is logged but silently discarded (never persisted).
    """
    await inspect_request(request, db, user_id=current_user.id)
    payload_str = json.dumps(body.model_dump())
    is_trap = await honeypot_gate(
        request, current_user, db, "DOCTOR_SUBMIT_NOTE", payload=payload_str
    )

    if is_trap:
        # Return a convincing success response; nothing is actually written.
        return {"detail": "Note saved successfully.", "honeypot": True}

    # Real path — in a full implementation, persist to a clinical_notes table
    log.info("Clinical note submitted by doctor %s for patient %s", current_user.id, body.patient_id)
    return {"detail": "Note saved successfully."}


@router.get("/portal/doctor/profile")
async def get_doctor_profile(
    request:      Request,
    current_user: User         = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    """Return the doctor's own profile data."""
    await inspect_request(request, db, user_id=current_user.id)
    is_trap = await honeypot_gate(request, current_user, db, "DOCTOR_VIEW_PROFILE")

    if is_trap:
        return _SHADOW_DOCTOR_PROFILE

    return {
        "id":        current_user.id,
        "npi":       current_user.npi,
        "full_name": current_user.full_name,
        "email":     current_user.email,
        "role":      current_user.role.value,
    }


# ---------------------------------------------------------------------------
# Patient Portal Endpoints
# ---------------------------------------------------------------------------

@router.get("/portal/patient/profile")
async def get_patient_profile(
    request:      Request,
    current_user: User         = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    """
    Return the patient's own record.
    Attackers receive a synthetic shadow record.
    """
    await inspect_request(request, db, user_id=current_user.id)
    is_trap = await honeypot_gate(request, current_user, db, "PATIENT_VIEW_PROFILE")

    if is_trap:
        return _SHADOW_PATIENT_SELF

    return {
        "id":        current_user.id,
        "mrn":       current_user.mrn,
        "full_name": current_user.full_name,
        "email":     current_user.email,
        "role":      current_user.role.value,
    }


@router.post("/portal/patient/appointment")
async def schedule_appointment(
    body:         ScheduleAppointmentBody,
    request:      Request,
    current_user: User         = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    """
    Schedule an appointment.
    Honeypot users get a convincing success response; nothing is persisted.
    """
    await inspect_request(request, db, user_id=current_user.id)
    payload_str = json.dumps(body.model_dump())
    is_trap = await honeypot_gate(
        request, current_user, db, "PATIENT_SCHEDULE_APPT", payload=payload_str
    )

    if is_trap:
        return {"detail": "Appointment scheduled successfully.", "honeypot": True}

    log.info("Appointment requested by patient %s: %s", current_user.id, body.datetime_str)
    return {"detail": "Appointment scheduled successfully."}


# ---------------------------------------------------------------------------
# Admin Endpoints
# ---------------------------------------------------------------------------

@router.get("/admin/audit-logs")
async def get_audit_logs(
    request:      Request,
    skip:         int          = 0,
    limit:        int          = 100,
    current_user: User         = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    """
    Return paginated audit logs. Admin role only.
    Honeypot routing does NOT apply here — admins are never trapped.
    """
    if current_user.role.value != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only.")

    result = await db.execute(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
    )
    logs = result.scalars().all()

    return {
        "total": len(logs),
        "logs": [
            {
                "id":                 l.id,
                "timestamp":          l.timestamp.isoformat() if l.timestamp else None,
                "ip_address":         l.ip_address,
                "user_id":            l.user_id,
                "action":             l.action,
                "endpoint":           l.endpoint,
                "http_method":        l.http_method,
                "is_malicious":       l.is_malicious,
                "is_honeypot_action": l.is_honeypot_action,
                "detection_reason":   l.detection_reason,
                "response_status":    l.response_status,
            }
            for l in logs
        ],
    }


@router.get("/admin/flagged-users")
async def get_flagged_users(
    request:      Request,
    current_user: User         = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    """Return all users flagged as attackers. Admin role only."""
    if current_user.role.value != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only.")

    result = await db.execute(
        select(User).where(User.is_flagged_as_attacker == True)  # noqa
    )
    flagged = result.scalars().all()

    return {
        "flagged_users": [
            {
                "id":                    u.id,
                "email":                 u.email,
                "role":                  u.role.value,
                "failed_login_count":    u.failed_login_count,
                "last_login_ip":         u.last_login_ip,
                "is_flagged_as_attacker":u.is_flagged_as_attacker,
            }
            for u in flagged
        ]
    }


@router.post("/admin/unflag-user/{user_id}")
async def unflag_user(
    user_id:      int,
    request:      Request,
    current_user: User         = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    """Manually clear the attacker flag on a user. Admin role only."""
    if current_user.role.value != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only.")

    result = await db.execute(select(User).where(User.id == user_id))
    target: Optional[User] = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    target.is_flagged_as_attacker = False
    target.failed_login_count = 0
    await db.commit()

    await write_audit_log(
        db, request, f"ADMIN_UNFLAG_USER:{user_id}", user_id=current_user.id
    )
    return {"detail": f"User {user_id} unflagged."}
