"""
findings.py — Vulnerability query and stats API routes.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from backend.database import get_db
from backend import models
from backend.schemas import VulnerabilityOut, VulnStats, DashboardStats

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("/", response_model=List[VulnerabilityOut])
def list_findings(
    scan_id: Optional[int] = Query(None),
    target_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    vuln_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(models.Vulnerability)
    if scan_id:
        q = q.filter(models.Vulnerability.scan_id == scan_id)
    if target_id:
        q = q.filter(models.Vulnerability.target_id == target_id)
    if severity:
        q = q.filter(models.Vulnerability.severity.ilike(severity))
    if vuln_type:
        q = q.filter(models.Vulnerability.vuln_type.ilike(f"%{vuln_type}%"))
    return q.order_by(models.Vulnerability.risk_score.desc()).all()


@router.get("/stats", response_model=VulnStats)
def vuln_stats(scan_id: Optional[int] = Query(None), db: Session = Depends(get_db)):
    q = db.query(models.Vulnerability)
    if scan_id:
        q = q.filter(models.Vulnerability.scan_id == scan_id)
    vulns = q.all()
    return VulnStats(
        total=len(vulns),
        critical=sum(1 for v in vulns if v.severity == "Critical"),
        high=sum(1 for v in vulns if v.severity == "High"),
        medium=sum(1 for v in vulns if v.severity == "Medium"),
        low=sum(1 for v in vulns if v.severity == "Low"),
        info=sum(1 for v in vulns if v.severity == "Info"),
    )


@router.get("/dashboard", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db)):
    targets = db.query(models.Target).count()
    scans = db.query(models.Scan).count()
    vulns = db.query(models.Vulnerability).all()

    recent_scans = (
        db.query(models.Scan)
        .order_by(models.Scan.created_at.desc())
        .limit(5)
        .all()
    )
    top_risks = (
        db.query(models.Vulnerability)
        .order_by(models.Vulnerability.risk_score.desc())
        .limit(10)
        .all()
    )

    from backend.schemas import ScanOut, VulnerabilityOut
    return DashboardStats(
        total_targets=targets,
        total_scans=scans,
        total_vulnerabilities=len(vulns),
        critical=sum(1 for v in vulns if v.severity == "Critical"),
        high=sum(1 for v in vulns if v.severity == "High"),
        medium=sum(1 for v in vulns if v.severity == "Medium"),
        low=sum(1 for v in vulns if v.severity == "Low"),
        info=sum(1 for v in vulns if v.severity == "Info"),
        recent_scans=[ScanOut.model_validate(s) for s in recent_scans],
        top_risks=[VulnerabilityOut.model_validate(v) for v in top_risks],
    )


@router.get("/{finding_id}", response_model=VulnerabilityOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    from fastapi import HTTPException
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.id == finding_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Finding not found")
    return vuln
