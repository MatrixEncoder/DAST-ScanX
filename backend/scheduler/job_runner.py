"""
job_runner.py — Async Scan Job Orchestrator.

Orchestrates the full DAST pipeline:
  1. Discover endpoints (crawler)
  2. Run scanners (Wapiti + Nuclei) — with demo fallback
  3. Normalize findings
  4. Correlate / deduplicate
  5. Score risks
  6. Persist to DB
"""

import logging
from datetime import datetime, timezone
from typing import List
from backend.scanners.base import RawFinding

from backend.database import SessionLocal
from backend import models
from backend.crawler.discovery import discover_endpoints
from backend.scanners.wapiti_scanner import WapitiScanner
from backend.scanners.nuclei_scanner import NucleiScanner
from backend.normalization.normalizer import normalize
from backend.correlation.correlator import correlate
from backend.scoring.risk_engine import score_vulnerabilities

logger = logging.getLogger(__name__)


def run_scan_job(scan_id: int):
    """
    Full DAST pipeline executed as a background task.
    Updates scan status in the DB at each stage.
    """
    db = SessionLocal()
    try:
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not scan:
            logger.error(f"[Job] Scan {scan_id} not found")
            return

        target = db.query(models.Target).filter(models.Target.id == scan.target_id).first()
        if not target:
            _fail_scan(db, scan, "Target not found")
            return

        # ── Stage 1: Running ──────────────────────────────────
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        logger.info(f"[Job] Scan {scan_id} started for {target.base_url}")

        # ── Stage 2: Attack Surface Discovery ────────────────
        try:
            discovered = discover_endpoints(target.base_url, max_depth=2, max_pages=30)
            endpoint_urls = [e["url"] for e in discovered]
            # Store endpoints
            for ep in discovered:
                endpoint = models.Endpoint(
                    target_id=target.id,
                    scan_id=scan.id,
                    url=ep["url"],
                    method=ep.get("method", "GET"),
                )
                db.add(endpoint)
            db.commit()
            logger.info(f"[Job] Discovered {len(discovered)} endpoints")
        except Exception as e:
            logger.warning(f"[Job] Discovery failed: {e}. Falling back to base URL.")
            endpoint_urls = [target.base_url]

        # ── Stage 3: DAST Scanning ────────────────────────────
        all_raw_findings = []

        wapiti = WapitiScanner()
        if wapiti.is_available():
            wapiti_findings = wapiti.scan(target.base_url, endpoint_urls)
        else:
            logger.info("[Job] Wapiti not installed")
            wapiti_findings = [RawFinding(
                title="Scanner Not Installed: Wapiti",
                vuln_type="Diagnostic",
                endpoint=target.base_url,
                severity="Info",
                confidence="High",
                description="The Wapiti DAST scanner is not installed on the server handling this scan.",
                evidence="System check failed to find 'wapiti' executable in PATH.",
                scanner_name="Wapiti"
            )]
        all_raw_findings.extend(wapiti_findings)

        nuclei = NucleiScanner()
        if nuclei.is_available():
            nuclei_findings = nuclei.scan(target.base_url, endpoint_urls)
        else:
            logger.info("[Job] Nuclei not installed")
            nuclei_findings = [RawFinding(
                title="Scanner Not Installed: Nuclei",
                vuln_type="Diagnostic",
                endpoint=target.base_url,
                severity="Info",
                confidence="High",
                description="The Nuclei DAST scanner is not installed on the server handling this scan.",
                evidence="System check failed to find 'nuclei' executable in PATH.",
                scanner_name="Nuclei"
            )]
        all_raw_findings.extend(nuclei_findings)

        logger.info(f"[Job] Total raw findings: {len(all_raw_findings)}")

        # ── Stage 4: Normalize ────────────────────────────────
        normalized = normalize(all_raw_findings)

        # ── Stage 5: Correlate ────────────────────────────────
        correlated = correlate(normalized)
        logger.info(f"[Job] After correlation: {len(correlated)} unique findings")

        # ── Stage 6: Score ────────────────────────────────────
        scored = score_vulnerabilities(correlated)

        # ── Stage 7: Persist Vulnerabilities ─────────────────
        for v in scored:
            vuln = models.Vulnerability(
                vuln_hash=v.vuln_uuid,
                scan_id=scan.id,
                target_id=target.id,
                title=v.title,
                vuln_type=v.vuln_type,
                endpoint=v.endpoint,
                severity=v.severity,
                confidence=v.confidence,
                risk_score=v.risk_score,
                description=v.description,
                evidence=v.evidence,
                owasp_category=v.owasp_category,
                detected_by=v.detected_by,
                remediation=v.remediation,
            )
            db.add(vuln)

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info(f"[Job] Scan {scan_id} completed with {len(scored)} findings")

    except Exception as e:
        logger.error(f"[Job] Scan {scan_id} failed: {e}", exc_info=True)
        try:
            _fail_scan(db, db.query(models.Scan).filter(models.Scan.id == scan_id).first(), str(e))
        except Exception:
            pass
    finally:
        db.close()


def _fail_scan(db, scan, message: str):
    if scan:
        scan.status = "failed"
        scan.error_message = message[:500]
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
