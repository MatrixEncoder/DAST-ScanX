"""
models.py — SQLAlchemy ORM models for all Scan-X entities.
"""

from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Float, Text, ForeignKey
import datetime
from datetime import timezone as tz

from backend.database import Base


class Target(Base):
    """A web application registered for scanning."""
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    base_url: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    auth_required: Mapped[bool] = mapped_column(default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=lambda: datetime.datetime.now(tz.utc))
    updated_at: Mapped[datetime.datetime] = mapped_column(default=lambda: datetime.datetime.now(tz.utc), onupdate=lambda: datetime.datetime.now(tz.utc))

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    endpoints: Mapped[list["Endpoint"]] = relationship("Endpoint", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    """A scanning job associated with a target."""
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    
    status: Mapped[str] = mapped_column(String(50), default="created")  # created, queued, running, completed, failed
    scanner: Mapped[str] = mapped_column(String(100)) # wapiti, nuclei, etc.
    
    # Store JSON string list of endpoints
    endpoints_discovered: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    created_at: Mapped[datetime.datetime] = mapped_column(default=lambda: datetime.datetime.now(tz.utc))
    started_at: Mapped[datetime.datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime.datetime | None] = mapped_column(nullable=True)

    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    endpoints: Mapped[list["Endpoint"]] = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Endpoint(Base):
    """A URL endpoint discovered during attack surface discovery."""
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    url: Mapped[str] = mapped_column(String(1024))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    discovered_at: Mapped[datetime.datetime] = mapped_column(default=lambda: datetime.datetime.now(tz.utc))

    target: Mapped["Target"] = relationship("Target", back_populates="endpoints")
    scan: Mapped["Scan"] = relationship("Scan", back_populates="endpoints") # Added back_populates for Scan


class Vulnerability(Base):
    """
    Normalized vulnerability records.
    """
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Core attributes
    title: Mapped[str] = mapped_column(String(255))
    vuln_type: Mapped[str] = mapped_column(String(100))  # e.g., 'SQLi', 'XSS', 'DirectoryTraversal'
    severity: Mapped[str] = mapped_column(String(20))    # Critical, High, Medium, Low, Info
    endpoint: Mapped[str] = mapped_column(String(1024))
    
    # Optional parameters or elements affected
    parameter: Mapped[str | None] = mapped_column(String(100), nullable=True)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    
    # Additional Context
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Meta
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    
    # Correlation & Scoring
    detected_by: Mapped[str] = mapped_column(String(100)) # e.g. 'wapiti', 'nuclei', 'multiple (wapiti,nuclei)'
    confidence: Mapped[str] = mapped_column(String(20), default="Certain") # Certain, Firm, Tentative
    risk_score: Mapped[float] = mapped_column(Float, default=0.0) # Composite score 0-10
    
    # Identity Hash (for deduplication)
    vuln_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    
    timestamp: Mapped[datetime.datetime] = mapped_column(default=lambda: datetime.datetime.now(tz.utc))

    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")
    target: Mapped["Target"] = relationship("Target", back_populates="vulnerabilities")


class Report(Base):
    """
    Generated security reports.
    """
    __tablename__ = "reports"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String(10)) # pdf, html
    filepath: Mapped[str] = mapped_column(String(512))
    generated_at: Mapped[datetime.datetime] = mapped_column(default=lambda: datetime.datetime.now(tz.utc))

    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")
