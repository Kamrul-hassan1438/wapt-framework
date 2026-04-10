import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, Float, Boolean,
    DateTime, ForeignKey, JSON, Enum as SAEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from db.database import Base
import enum


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enums ──────────────────────────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanType(str, enum.Enum):
    FULL      = "full"
    RECON     = "recon"
    SCAN      = "scan"
    VULN      = "vuln"
    AUTH      = "auth"
    CUSTOM    = "custom"


# ── Models ─────────────────────────────────────────────────────────────────

class Target(Base):
    """A target web application to test."""
    __tablename__ = "targets"

    id:          Mapped[str]           = mapped_column(String(36), primary_key=True, default=new_uuid)
    name:        Mapped[str]           = mapped_column(String(255), nullable=False)
    url:         Mapped[str]           = mapped_column(String(2048), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scope_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # written permission notes
    is_active:   Mapped[bool]          = mapped_column(Boolean, default=True)
    created_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target id={self.id} name={self.name} url={self.url}>"


class Scan(Base):
    """A single penetration test scan run against a target."""
    __tablename__ = "scans"

    id:          Mapped[str]           = mapped_column(String(36), primary_key=True, default=new_uuid)
    target_id:   Mapped[str]           = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    scan_type:   Mapped[ScanType]      = mapped_column(SAEnum(ScanType), default=ScanType.FULL)
    status:      Mapped[ScanStatus]    = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    modules_run: Mapped[Optional[dict]]= mapped_column(JSON, nullable=True)   # list of module names
    config_used: Mapped[Optional[dict]]= mapped_column(JSON, nullable=True)   # snapshot of scan config
    started_at:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=utcnow)
    error_msg:   Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    target:   Mapped["Target"]         = relationship("Target", back_populates="scans")
    findings: Mapped[list["Finding"]]  = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    requests: Mapped[list["RequestLog"]] = relationship("RequestLog", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} type={self.scan_type} status={self.status}>"


class Finding(Base):
    """A single vulnerability finding discovered during a scan."""
    __tablename__ = "findings"

    id:               Mapped[str]            = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id:          Mapped[str]            = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    title:            Mapped[str]            = mapped_column(String(500), nullable=False)
    severity:         Mapped[Severity]       = mapped_column(SAEnum(Severity), nullable=False)
    cvss_score:       Mapped[Optional[float]]= mapped_column(Float, nullable=True)
    vuln_type:        Mapped[str]            = mapped_column(String(100), nullable=False)   # e.g. "sqli", "xss"
    url:              Mapped[str]            = mapped_column(String(2048), nullable=False)
    parameter:        Mapped[Optional[str]]  = mapped_column(String(255), nullable=True)    # affected param
    payload_used:     Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    evidence:         Mapped[Optional[str]]  = mapped_column(Text, nullable=True)           # raw response snippet
    description:      Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    remediation:      Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    references:       Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)           # list of URLs
    is_false_positive:Mapped[bool]           = mapped_column(Boolean, default=False)
    confirmed:        Mapped[bool]           = mapped_column(Boolean, default=False)
    created_at:       Mapped[datetime]       = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity} type={self.vuln_type}>"


class RequestLog(Base):
    """Audit log of every HTTP request sent during a scan."""
    __tablename__ = "request_logs"

    id:           Mapped[str]            = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id:      Mapped[str]            = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    method:       Mapped[str]            = mapped_column(String(10), nullable=False)
    url:          Mapped[str]            = mapped_column(String(2048), nullable=False)
    req_headers:  Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    req_body:     Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    status_code:  Mapped[Optional[int]]  = mapped_column(Integer, nullable=True)
    res_headers:  Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    res_body:     Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    duration_ms:  Mapped[Optional[float]]= mapped_column(Float, nullable=True)
    module:       Mapped[Optional[str]]  = mapped_column(String(100), nullable=True)  # which module sent it
    created_at:   Mapped[datetime]       = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="requests")