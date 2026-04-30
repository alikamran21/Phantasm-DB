# api/_models.py
"""
SQLAlchemy ORM models — shared across all Vercel serverless functions.
Underscore prefix prevents Vercel treating this as an API route.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, func,
)
from sqlalchemy.orm import relationship

from _db import Base


class UserRole(str, enum.Enum):
    admin   = "admin"
    doctor  = "doctor"
    patient = "patient"


class User(Base):
    __tablename__ = "users"

    id                     = Column(Integer, primary_key=True, index=True)
    email                  = Column(String(255), unique=True, nullable=False, index=True)
    password_hash          = Column(String(255), nullable=False)
    role                   = Column(Enum(UserRole), nullable=False, default=UserRole.patient)
    full_name              = Column(String(255), nullable=True)
    mrn                    = Column(String(50),  unique=True, nullable=True, index=True)
    npi                    = Column(String(50),  unique=True, nullable=True, index=True)
    is_active              = Column(Boolean, default=True,  nullable=False)
    is_flagged_as_attacker = Column(Boolean, default=False, nullable=False, index=True)
    failed_login_count     = Column(Integer, default=0,     nullable=False)
    last_login_ip          = Column(String(64), nullable=True)
    created_at             = Column(DateTime(timezone=True), server_default=func.now())
    updated_at             = Column(DateTime(timezone=True), onupdate=func.now())

    audit_logs   = relationship("AuditLog",   back_populates="user", lazy="select")
    otp_requests = relationship("OTPRequest", back_populates="user", lazy="select")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id                 = Column(Integer, primary_key=True, index=True)
    timestamp          = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    ip_address         = Column(String(64),  nullable=False, index=True)
    user_agent         = Column(String(512), nullable=True)
    user_id            = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action             = Column(String(128), nullable=False)
    endpoint           = Column(String(512), nullable=False)
    http_method        = Column(String(10),  nullable=False, default="GET")
    payload            = Column(Text,        nullable=True)
    response_status    = Column(Integer,     nullable=True)
    is_malicious       = Column(Boolean, default=False, nullable=False, index=True)
    is_honeypot_action = Column(Boolean, default=False, nullable=False, index=True)
    detection_reason   = Column(String(512), nullable=True)

    user = relationship("User", back_populates="audit_logs")


class OTPRequest(Base):
    __tablename__ = "otp_requests"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    otp_code   = Column(String(6),  nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used    = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_ip = Column(String(64), nullable=True)

    user = relationship("User", back_populates="otp_requests")

    def is_valid(self) -> bool:
        return (not self.is_used) and (datetime.now(timezone.utc) < self.expires_at)
