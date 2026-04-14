"""
schemas.py — Pydantic v2 request/response schemas for the Scan-X API.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


# ─────────────────────────────────────────────────────────────
# Target schemas
# ─────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    name: str
    base_url: str
    auth_required: bool = False
    notes: str = ""


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    auth_required: Optional[bool] = None
    notes: Optional[str] = None


class TargetOut(BaseModel):
    id: int
    name: str
    base_url: str
    auth_required: bool
    notes: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────
# Scan schemas
# ─────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    target_id: int
    scanner: str = "wapiti+nuclei"


class ScanOut(BaseModel):
    id: int
    target_id: int
    status: str
    scanner: str
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────
# Vulnerability schemas
# ─────────────────────────────────────────────────────────────

class VulnerabilityOut(BaseModel):
    id: int
    vuln_hash: str
    scan_id: Optional[int] = None
    target_id: int
    title: str
    vuln_type: str
    endpoint: str
    severity: str
    confidence: str
    risk_score: float
    description: Optional[str] = None
    evidence: Optional[str] = None
    owasp_category: Optional[str] = None
    detected_by: str
    remediation: Optional[str] = None
    timestamp: datetime

    model_config = {"from_attributes": True}


class VulnStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


# ─────────────────────────────────────────────────────────────
# Dashboard schema
# ─────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_targets: int
    total_scans: int
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    recent_scans: List[ScanOut]
    top_risks: List[VulnerabilityOut]


# ─────────────────────────────────────────────────────────────
# Report schemas
# ─────────────────────────────────────────────────────────────

class ReportOut(BaseModel):
    id: int
    scan_id: int
    format: str
    filepath: str
    generated_at: datetime

    model_config = {"from_attributes": True}
