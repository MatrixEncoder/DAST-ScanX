"""
reports.py — Report generation and download API routes.
"""

import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List

from backend.database import get_db
from backend import models
from backend.schemas import ReportOut
from backend.reporting.html_report import generate_html_report
from backend.reporting.pdf_report import generate_pdf_report

router = APIRouter(prefix="/reports", tags=["Reports"])

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORTS_DIR = os.path.join(BASE_DIR, "database", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


@router.post("/{scan_id}/generate", response_model=List[ReportOut], status_code=201)
def generate_reports(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target = db.query(models.Target).filter(models.Target.id == scan.target_id).first()
    vulns = (
        db.query(models.Vulnerability)
        .filter(models.Vulnerability.scan_id == scan_id)
        .order_by(models.Vulnerability.risk_score.desc())
        .all()
    )

    reports_created = []

    # HTML
    html_path = os.path.join(REPORTS_DIR, f"scan_{scan_id}_report.html")
    generate_html_report(scan, target, vulns, html_path)
    html_report = _upsert_report(db, scan_id, "html", html_path)
    reports_created.append(html_report)

    # PDF
    pdf_path = os.path.join(REPORTS_DIR, f"scan_{scan_id}_report.pdf")
    try:
        generate_pdf_report(html_path, pdf_path)
        pdf_report = _upsert_report(db, scan_id, "pdf", pdf_path)
        reports_created.append(pdf_report)
    except Exception as e:
        # PDF generation is optional (requires WeasyPrint + GTK libs)
        pass

    return reports_created


@router.get("/{scan_id}", response_model=List[ReportOut])
def list_reports(scan_id: int, db: Session = Depends(get_db)):
    return db.query(models.Report).filter(models.Report.scan_id == scan_id).all()


@router.get("/{scan_id}/download/{format}")
def download_report(scan_id: int, format: str, db: Session = Depends(get_db)):
    if format not in ("html", "pdf"):
        raise HTTPException(status_code=400, detail="Format must be 'html' or 'pdf'")
    report = (
        db.query(models.Report)
        .filter(models.Report.scan_id == scan_id, models.Report.format == format)
        .first()
    )
    if not report or not os.path.exists(report.filepath):
        raise HTTPException(status_code=404, detail="Report not found — generate it first")
    media_type = "text/html" if format == "html" else "application/pdf"
    headers = {
        "Content-Disposition": f'attachment; filename="{os.path.basename(report.filepath)}"'
    }
    return FileResponse(report.filepath, media_type=media_type, headers=headers)


def _upsert_report(db: Session, scan_id: int, fmt: str, filepath: str) -> models.Report:
    existing = db.query(models.Report).filter(
        models.Report.scan_id == scan_id, models.Report.format == fmt
    ).first()
    if existing:
        existing.filepath = filepath
        db.commit()
        db.refresh(existing)
        return existing
    r = models.Report(scan_id=scan_id, format=fmt, filepath=filepath)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r
