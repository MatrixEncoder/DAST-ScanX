"""
scans.py — Scan management and job launching API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List

from backend.database import get_db
from backend import models
from backend.schemas import ScanCreate, ScanOut
from backend.scheduler.job_runner import run_scan_job

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("/", response_model=List[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(models.Scan).order_by(models.Scan.created_at.desc()).all()


@router.post("/", response_model=ScanOut, status_code=201)
def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Verify target exists
    target = db.query(models.Target).filter(models.Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = models.Scan(
        target_id=payload.target_id,
        scanner=payload.scanner,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch scan job in background
    background_tasks.add_task(run_scan_job, scan.id)
    return scan


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in status '{scan.status}'")
    scan.status = "failed"
    scan.error_message = "Cancelled by user"
    db.commit()
    db.refresh(scan)
    return scan
