# api/_models.py
"""
SQLAlchemy ORM — Full ERD implementation for Phantasm-DB / Serenity EHR.

ISA Hierarchy (Total Completeness, Disjoint):
  Global_Identities  (Superclass)
    ├── Production_Users  ──► Doctor   (Sub-Tier 2)
    │                    └──► Patient  (Sub-Tier 2)
    └── Threat_Actors

Clinical Wing:
  Doctor ─(Treats 1:N)──────────────────────────────────────► Patient
  Patient ─(Has M:N via Patient_Symptoms associative)──────► Psych_Symptoms

Security & Honeypot Wing:
  Global_Identities ─(Generates 1:N)──► Forensic_Ledger
  Forensic_Ledger   ─(Triggers 1:N)──► Real_Time_Alerts  [weak entity]
  Forensic_Ledger   ─(Flags M:N)─────► Detection_Policies
  System_State      ─(Orchestrates 1:N)► Shadow_Manifest
  Shadow_Manifest   ─(Utilizes 1:N)──► Lure_Blueprints
  Shadow_Manifest   ─(Contains 1:N)──► Honey_Tokens

Operational (not in ERD, required for runtime):
  OTP_Requests  — MFA flow; links to production_users
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum as SAEnum,
    Float, ForeignKey, Integer, JSON, String, Text, func,
)
from sqlalchemy.orm import relationship

from _db import Base


# ============================================================================
# ENUMERATIONS
# ============================================================================

class ThreatClass(str, enum.Enum):
    sql_injection  = "SQL_INJECTION"
    xss            = "XSS"
    path_traversal = "PATH_TRAVERSAL"
    cmd_injection  = "COMMAND_INJECTION"
    brute_force    = "BRUTE_FORCE"
    rate_limit     = "RATE_LIMIT"
    reconnaissance = "RECONNAISSANCE"
    unknown        = "UNKNOWN"


class EscalationLevel(str, enum.Enum):
    low      = "LOW"
    medium   = "MEDIUM"
    high     = "HIGH"
    critical = "CRITICAL"


class UserRole(str, enum.Enum):
    admin   = "admin"
    doctor  = "doctor"
    patient = "patient"


# ============================================================================
# SUPERCLASS — Global_Identities
# ERD: Strong entity, root of ISA hierarchy
# Attrs: identity_id (PK), ip_address, mac_address, risk_score
# ============================================================================

class GlobalIdentity(Base):
    """
    Root superclass for ALL principals — legitimate users and threat actors.
    Total completeness: every row has exactly one subclass row.
    Disjoint: cannot be both Production_User and Threat_Actor.
    """
    __tablename__ = "global_identities"

    identity_id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address  = Column(String(64),  nullable=False, index=True)
    mac_address = Column(String(64),  nullable=True)
    risk_score  = Column(Float,       nullable=False, default=0.0)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now())

    production_user = relationship("ProductionUser", back_populates="identity",
                                   uselist=False, lazy="select")
    threat_actor    = relationship("ThreatActor", back_populates="identity",
                                   uselist=False, lazy="select")
    forensic_logs   = relationship("ForensicLedger", back_populates="identity",
                                   lazy="select")


# ============================================================================
# SUB-TIER 1 — Production_Users
# ERD: Subclass of Global_Identities
# Attrs: identity_id (PK/FK), username, password_hash, mfa_enabled
# ============================================================================

class ProductionUser(Base):
    """Legitimate system users. ISA subclass of GlobalIdentity."""
    __tablename__ = "production_users"

    identity_id   = Column(Integer, ForeignKey("global_identities.identity_id",
                            ondelete="CASCADE"), primary_key=True)
    username      = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    mfa_enabled   = Column(Boolean, default=True, nullable=False)

    # Operational additions
    email                  = Column(String(255), unique=True, nullable=False, index=True)
    role                   = Column(SAEnum(UserRole), nullable=False, default=UserRole.patient)
    is_active              = Column(Boolean, default=True, nullable=False)
    is_flagged_as_attacker = Column(Boolean, default=False, nullable=False, index=True)
    failed_login_count     = Column(Integer, default=0, nullable=False)
    last_login_ip          = Column(String(64), nullable=True)
    last_login_at          = Column(DateTime(timezone=True), nullable=True)
    created_at             = Column(DateTime(timezone=True), server_default=func.now())
    updated_at             = Column(DateTime(timezone=True), onupdate=func.now())

    identity        = relationship("GlobalIdentity", back_populates="production_user")
    doctor_profile  = relationship("Doctor",  back_populates="user", uselist=False, lazy="select")
    patient_profile = relationship("Patient", back_populates="user", uselist=False, lazy="select")
    otp_requests    = relationship("OTPRequest", back_populates="user",
                                   foreign_keys="OTPRequest.user_id", lazy="select")


# ============================================================================
# SUB-TIER 2 — Doctor
# ERD: Subclass of Production_Users
# Attrs: identity_id (PK/FK), license_no, specialization
# ============================================================================

class Doctor(Base):
    """Doctor subclass. Treats Patients (1:N, partial for doctor)."""
    __tablename__ = "doctors"

    identity_id    = Column(Integer, ForeignKey("production_users.identity_id",
                             ondelete="CASCADE"), primary_key=True)
    license_no     = Column(String(100), unique=True, nullable=False, index=True)
    specialization = Column(String(255), nullable=True)
    department     = Column(String(255), nullable=True)
    accepting_patients = Column(Boolean, default=True, nullable=False)

    user     = relationship("ProductionUser", back_populates="doctor_profile")
    patients = relationship("Patient", back_populates="attending_doctor",
                            foreign_keys="Patient.attending_doctor_id", lazy="select")


# ============================================================================
# SUB-TIER 2 — Patient
# ERD: Subclass of Production_Users
# Attrs: identity_id (PK/FK), ssn, dob, patient_name (composite → first+last),
#        phone_numbers (multivalued → PatientPhone table), age (derived from dob)
# ============================================================================

class Patient(Base):
    """Patient subclass. Must have a doctor (total participation in Treats)."""
    __tablename__ = "patients"

    identity_id = Column(Integer, ForeignKey("production_users.identity_id",
                          ondelete="CASCADE"), primary_key=True)
    ssn         = Column(String(20),  unique=True, nullable=True)
    dob         = Column(DateTime(timezone=True), nullable=True)

    # Composite attribute: patient_name → first_name + last_name
    first_name  = Column(String(100), nullable=True)
    last_name   = Column(String(100), nullable=True)

    # Operational
    mrn            = Column(String(50), unique=True, nullable=True, index=True)
    diagnosis      = Column(String(512), nullable=True)
    next_appointment = Column(DateTime(timezone=True), nullable=True)
    medications    = Column(JSON, nullable=True)
    clinical_notes = Column(Text, nullable=True)

    # FK to Doctor — total participation (patient must have a doctor)
    attending_doctor_id = Column(Integer, ForeignKey("doctors.identity_id",
                                  ondelete="SET NULL"), nullable=True, index=True)

    user             = relationship("ProductionUser", back_populates="patient_profile")
    attending_doctor = relationship("Doctor", back_populates="patients",
                                    foreign_keys=[attending_doctor_id])
    phone_numbers    = relationship("PatientPhone", back_populates="patient",
                                    cascade="all, delete-orphan", lazy="select")
    symptoms         = relationship("PatientSymptom", back_populates="patient",
                                    cascade="all, delete-orphan", lazy="select")

    @property
    def age(self) -> "int | None":
        """Derived attribute — computed from dob (not stored)."""
        if not self.dob:
            return None
        d = self.dob if self.dob.tzinfo else self.dob.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - d).days // 365

    @property
    def patient_name(self) -> str:
        """Composite attribute accessor."""
        return " ".join(p for p in [self.first_name, self.last_name] if p)


# ============================================================================
# Multivalued Attribute — PatientPhone
# ERD: phone_numbers is a double-oval (multivalued) on Patient
# ============================================================================

class PatientPhone(Base):
    __tablename__ = "patient_phones"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    patient_id = Column(Integer, ForeignKey("patients.identity_id",
                         ondelete="CASCADE"), nullable=False, index=True)
    phone      = Column(String(30), nullable=False)
    label      = Column(String(50), nullable=True)   # "mobile", "home", "emergency"

    patient = relationship("Patient", back_populates="phone_numbers")


# ============================================================================
# Strong Entity — Psych_Symptoms
# ERD: symptom_id (PK), name, clinical_desc
# ============================================================================

class PsychSymptom(Base):
    __tablename__ = "psych_symptoms"

    symptom_id    = Column(Integer, primary_key=True, autoincrement=True)
    name          = Column(String(255), unique=True, nullable=False)
    clinical_desc = Column(Text, nullable=True)
    icd10_code    = Column(String(20), nullable=True)

    patient_symptoms = relationship("PatientSymptom", back_populates="symptom", lazy="select")


# ============================================================================
# Associative Entity — Patient_Symptoms  (M:N: Patient ↔ Psych_Symptoms)
# ERD: identity_id (PK/FK), symptom_id (PK/FK), severity_level, onset_date
# ============================================================================

class PatientSymptom(Base):
    """Junction entity with attributes for the Treats-like M:N relationship."""
    __tablename__ = "patient_symptoms"

    patient_id     = Column(Integer, ForeignKey("patients.identity_id",
                             ondelete="CASCADE"), primary_key=True)
    symptom_id     = Column(Integer, ForeignKey("psych_symptoms.symptom_id",
                             ondelete="CASCADE"), primary_key=True)
    severity_level = Column(String(50), nullable=True)
    onset_date     = Column(DateTime(timezone=True), nullable=True)
    notes          = Column(Text, nullable=True)

    patient = relationship("Patient",      back_populates="symptoms")
    symptom = relationship("PsychSymptom", back_populates="patient_symptoms")


# ============================================================================
# SUB-TIER 1 — Threat_Actors
# ERD: Subclass of Global_Identities (disjoint from Production_Users)
# Attrs: identity_id (PK/FK), fingerprint_hash, threat_class,
#        total_attacks (Derived — computed from forensic log count)
# ============================================================================

class ThreatActor(Base):
    __tablename__ = "threat_actors"

    identity_id      = Column(Integer, ForeignKey("global_identities.identity_id",
                               ondelete="CASCADE"), primary_key=True)
    fingerprint_hash = Column(String(255), nullable=True, index=True)
    threat_class     = Column(SAEnum(ThreatClass), nullable=False, default=ThreatClass.unknown)
    first_seen_at    = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at     = Column(DateTime(timezone=True), onupdate=func.now())
    is_blocked       = Column(Boolean, default=False, nullable=False)
    notes            = Column(Text, nullable=True)

    identity = relationship("GlobalIdentity", back_populates="threat_actor")

    @property
    def total_attacks(self) -> int:
        """Derived attribute — count from linked forensic logs."""
        return len(self.identity.forensic_logs) if self.identity else 0


# ============================================================================
# Strong Entity — Forensic_Ledger  (replaces old audit_logs)
# ERD: log_id (PK), raw_query, duration_ms, was_deceived
# 1:N from Global_Identities — total participation (log must have identity)
# ============================================================================

class ForensicLedger(Base):
    __tablename__ = "forensic_ledger"

    log_id          = Column(Integer, primary_key=True, autoincrement=True)
    raw_query       = Column(Text,    nullable=True)
    duration_ms     = Column(Float,   nullable=True)
    was_deceived    = Column(Boolean, default=False, nullable=False)

    # Total participation — cannot be null
    identity_id     = Column(Integer, ForeignKey("global_identities.identity_id",
                              ondelete="RESTRICT"), nullable=False, index=True)

    # Operational audit fields
    timestamp       = Column(DateTime(timezone=True), server_default=func.now(),
                             nullable=False, index=True)
    action          = Column(String(128), nullable=False)
    endpoint        = Column(String(512), nullable=False)
    http_method     = Column(String(10),  nullable=False, default="GET")
    response_status = Column(Integer,     nullable=True)
    user_agent      = Column(String(512), nullable=True)
    is_malicious    = Column(Boolean, default=False, nullable=False, index=True)
    detection_reason= Column(String(512), nullable=True)

    # Back-compat: keep user_id for API responses (mirrors production_users.identity_id)
    user_id         = Column(Integer, ForeignKey("production_users.identity_id",
                              ondelete="SET NULL"), nullable=True, index=True)

    identity         = relationship("GlobalIdentity", back_populates="forensic_logs")
    real_time_alerts = relationship("RealTimeAlert", back_populates="ledger_entry",
                                    cascade="all, delete-orphan", lazy="select")
    matched_policies = relationship("LedgerPolicyMatch", back_populates="ledger_entry",
                                    cascade="all, delete-orphan", lazy="select")


# ============================================================================
# Weak Entity — Real_Time_Alerts
# ERD: alert_no (Partial Key), escalation_level, is_acknowledged
# Identifying owner: Forensic_Ledger "Triggers" Real_Time_Alerts (1:N)
# ============================================================================

class RealTimeAlert(Base):
    __tablename__ = "real_time_alerts"

    log_id            = Column(Integer, ForeignKey("forensic_ledger.log_id",
                                ondelete="CASCADE"), primary_key=True)
    alert_no          = Column(Integer, primary_key=True)   # partial key
    escalation_level  = Column(SAEnum(EscalationLevel), nullable=False,
                                default=EscalationLevel.medium)
    is_acknowledged   = Column(Boolean, default=False, nullable=False)
    triggered_at      = Column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at   = Column(DateTime(timezone=True), nullable=True)
    acknowledged_by   = Column(Integer, ForeignKey("production_users.identity_id",
                                ondelete="SET NULL"), nullable=True)
    message           = Column(String(512), nullable=True)

    ledger_entry = relationship("ForensicLedger", back_populates="real_time_alerts")


# ============================================================================
# Strong Entity — Detection_Policies
# ERD: policy_id (PK), regex_pattern, risk_weight
# M:N with Forensic_Ledger via LedgerPolicyMatch
# ============================================================================

class DetectionPolicy(Base):
    __tablename__ = "detection_policies"

    policy_id     = Column(Integer, primary_key=True, autoincrement=True)
    regex_pattern = Column(String(512), nullable=False)
    risk_weight   = Column(Float, nullable=False, default=1.0)
    name          = Column(String(255), nullable=False, unique=True)
    category      = Column(String(100), nullable=False)
    is_active     = Column(Boolean, default=True, nullable=False)
    description   = Column(Text, nullable=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())

    ledger_matches = relationship("LedgerPolicyMatch", back_populates="policy",
                                   cascade="all, delete-orphan", lazy="select")


class LedgerPolicyMatch(Base):
    """Junction table for the M:N 'Flags' relationship."""
    __tablename__ = "ledger_policy_matches"

    log_id          = Column(Integer, ForeignKey("forensic_ledger.log_id",
                              ondelete="CASCADE"), primary_key=True)
    policy_id       = Column(Integer, ForeignKey("detection_policies.policy_id",
                              ondelete="CASCADE"), primary_key=True)
    matched_at      = Column(DateTime(timezone=True), server_default=func.now())
    matched_snippet = Column(String(256), nullable=True)

    ledger_entry = relationship("ForensicLedger",  back_populates="matched_policies")
    policy       = relationship("DetectionPolicy", back_populates="ledger_matches")


# ============================================================================
# Strong Entity — System_State
# ERD: config_id (PK), throttle_delay, deception_active
# 1:N → Shadow_Manifest (total for manifest)
# ============================================================================

class SystemState(Base):
    __tablename__ = "system_state"

    config_id         = Column(Integer, primary_key=True, autoincrement=True)
    throttle_delay    = Column(Integer, nullable=False, default=0)
    deception_active  = Column(Boolean, nullable=False, default=True)
    name              = Column(String(100), nullable=False, default="default")
    rate_limit_max    = Column(Integer, nullable=False, default=30)
    rate_limit_window = Column(Integer, nullable=False, default=60)
    max_failed_logins = Column(Integer, nullable=False, default=5)
    otp_expire_mins   = Column(Integer, nullable=False, default=5)
    updated_at        = Column(DateTime(timezone=True), onupdate=func.now())
    updated_by        = Column(Integer, ForeignKey("production_users.identity_id",
                                ondelete="SET NULL"), nullable=True)

    shadow_manifests = relationship("ShadowManifest", back_populates="system_state",
                                    lazy="select")


# ============================================================================
# Strong Entity — Shadow_Manifest
# ERD: manifest_id (PK), prod_schema, shadow_schema
# ============================================================================

class ShadowManifest(Base):
    __tablename__ = "shadow_manifests"

    manifest_id   = Column(Integer, primary_key=True, autoincrement=True)
    prod_schema   = Column(String(255), nullable=False)
    shadow_schema = Column(String(255), nullable=False)
    config_id     = Column(Integer, ForeignKey("system_state.config_id",
                            ondelete="CASCADE"), nullable=False, index=True)
    is_active     = Column(Boolean, default=True, nullable=False)
    description   = Column(Text, nullable=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())

    system_state    = relationship("SystemState",   back_populates="shadow_manifests")
    lure_blueprints = relationship("LureBlueprint", back_populates="manifest",
                                   cascade="all, delete-orphan", lazy="select")
    honey_tokens    = relationship("HoneyToken",    back_populates="manifest",
                                   cascade="all, delete-orphan", lazy="select")


# ============================================================================
# Strong Entity — Lure_Blueprints
# ERD: blueprint_id (PK), rules_jsonb, faker_provider
# ============================================================================

class LureBlueprint(Base):
    __tablename__ = "lure_blueprints"

    blueprint_id   = Column(Integer, primary_key=True, autoincrement=True)
    rules_jsonb    = Column(JSON,        nullable=False)
    faker_provider = Column(String(255), nullable=False)
    manifest_id    = Column(Integer, ForeignKey("shadow_manifests.manifest_id",
                             ondelete="CASCADE"), nullable=False, index=True)
    name           = Column(String(255), nullable=True)
    is_active      = Column(Boolean, default=True, nullable=False)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())

    manifest = relationship("ShadowManifest", back_populates="lure_blueprints")


# ============================================================================
# Strong Entity — Honey_Tokens
# ERD: token_id (PK), target_pk_val, trigger_severity
# ============================================================================

class HoneyToken(Base):
    __tablename__ = "honey_tokens"

    token_id         = Column(Integer, primary_key=True, autoincrement=True)
    target_pk_val    = Column(String(255), nullable=False)
    trigger_severity = Column(SAEnum(EscalationLevel), nullable=False,
                               default=EscalationLevel.high)
    manifest_id      = Column(Integer, ForeignKey("shadow_manifests.manifest_id",
                               ondelete="CASCADE"), nullable=False, index=True)
    token_value      = Column(String(512), nullable=False, unique=True)
    field_name       = Column(String(100), nullable=True)
    is_triggered     = Column(Boolean, default=False, nullable=False)
    triggered_at     = Column(DateTime(timezone=True), nullable=True)
    triggered_by_ip  = Column(String(64), nullable=True)
    created_at       = Column(DateTime(timezone=True), server_default=func.now())

    manifest = relationship("ShadowManifest", back_populates="honey_tokens")


# ============================================================================
# Operational — OTPRequest  (not in ERD — required for MFA)
# ============================================================================

class OTPRequest(Base):
    __tablename__ = "otp_requests"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_id    = Column(Integer, ForeignKey("production_users.identity_id",
                         ondelete="CASCADE"), nullable=False, index=True)
    otp_code   = Column(String(6),  nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used    = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_ip = Column(String(64), nullable=True)

    user = relationship("ProductionUser", back_populates="otp_requests",
                        foreign_keys=[user_id])

    def is_valid(self) -> bool:
        return (not self.is_used) and (datetime.now(timezone.utc) < self.expires_at)


# ============================================================================
# Backward-compatibility aliases
# Existing API files import User / AuditLog — these keep them working.
# ============================================================================
User     = ProductionUser  # noqa
AuditLog = ForensicLedger  # noqa
