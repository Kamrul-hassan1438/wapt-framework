from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional, List
from datetime import datetime
from db.models import ScanStatus, Severity, ScanType


class TargetCreate(BaseModel):
    name: str
    url: str
    description: Optional[str] = None
    scope_notes: Optional[str] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")


class TargetResponse(BaseModel):
    id: str
    name: str
    url: str
    description: Optional[str]
    scope_notes: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    target_id: str
    scan_type: ScanType = ScanType.FULL
    rate_limit: Optional[int] = None
    timeout: Optional[int] = None


class ScanResponse(BaseModel):
    id: str
    target_id: str
    scan_type: ScanType
    status: ScanStatus
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    error_msg: Optional[str]

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: Severity
    cvss_score: Optional[float]
    vuln_type: str
    url: str
    parameter: Optional[str]
    description: Optional[str]
    remediation: Optional[str]
    is_false_positive: bool
    confirmed: bool
    created_at: datetime

    class Config:
        from_attributes = True