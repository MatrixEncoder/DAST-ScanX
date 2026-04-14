"""
seed_demo.py — Populate the Scan-X database with a realistic demo target,
scan, and vulnerability findings for presentation purposes.

Usage:
    cd c:\\Scan-X
    python scripts/seed_demo.py
"""

import sys
import os
import hashlib
import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import SessionLocal, init_db
from backend import models

DEMO_TARGET_URL = "http://testphp.vulnweb.com"
DEMO_TARGET_NAME = "Acunetix Test PHP App"

DEMO_VULNS = [
    {
        "title": "SQL Injection (Login Form)",
        "vuln_type": "SQL Injection",
        "severity": "Critical",
        "endpoint": f"{DEMO_TARGET_URL}/userinfo.php",
        "confidence": "High",
        "risk_score": 9.0,
        "description": "The login form is vulnerable to SQL injection. User-supplied input in the 'uname' parameter is not sanitised and is directly incorporated into SQL queries, allowing authentication bypass.",
        "evidence": "Parameter: uname, Payload: admin' OR '1'='1'--\nHTTP 200 response with 'Welcome admin' page content",
        "owasp_category": "A03:2021 – Injection",
        "detected_by": "Wapiti, Nuclei",
        "remediation": "Use parameterised queries or prepared statements. Implement an ORM layer. Apply strict input validation and deny lists.",
    },
    {
        "title": "Reflected Cross-Site Scripting (Search)",
        "vuln_type": "Cross-Site Scripting",
        "severity": "High",
        "endpoint": f"{DEMO_TARGET_URL}/search.php",
        "confidence": "High",
        "risk_score": 7.5,
        "description": "The 'searchFor' parameter reflects user input into the page without encoding, allowing execution of arbitrary JavaScript in the victim's browser.",
        "evidence": "Parameter: searchFor, Payload: <script>alert(document.cookie)</script>\nResponse body contains unescaped payload",
        "owasp_category": "A03:2021 – Injection",
        "detected_by": "Wapiti",
        "remediation": "Encode all user-supplied data before rendering in HTML. Implement a strict Content-Security-Policy header. Use framework-provided auto-escaping mechanisms.",
    },
    {
        "title": "Directory Traversal (File Parameter)",
        "vuln_type": "Path Traversal",
        "severity": "High",
        "endpoint": f"{DEMO_TARGET_URL}/showimage.php",
        "confidence": "High",
        "risk_score": 7.0,
        "description": "The 'file' parameter allows path traversal sequences, enabling reading of arbitrary files outside the web root including /etc/passwd.",
        "evidence": "Parameter: file, Payload: ../../etc/passwd\nResponse contains root:x:0:0:",
        "owasp_category": "A01:2021 – Broken Access Control",
        "detected_by": "Wapiti",
        "remediation": "Validate and sanitise file path inputs. Use allowlists for permitted paths. Chroot the web server process.",
    },
    {
        "title": "Exposed phpMyAdmin Interface",
        "vuln_type": "Sensitive File Exposure",
        "severity": "High",
        "endpoint": f"{DEMO_TARGET_URL}/phpmyadmin/",
        "confidence": "High",
        "risk_score": 8.0,
        "description": "phpMyAdmin is accessible without adequate access controls, exposing full database management capabilities to any unauthenticated user.",
        "evidence": "Template: phpmyadmin-panel | HTTP 200 OK — phpMyAdmin login panel served",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "detected_by": "Nuclei",
        "remediation": "Restrict access to /phpmyadmin/ by IP allowlist. Require strong authentication. Consider removing phpMyAdmin from production servers.",
    },
    {
        "title": "CORS Misconfiguration (Wildcard Origin)",
        "vuln_type": "CORS Misconfiguration",
        "severity": "Medium",
        "endpoint": f"{DEMO_TARGET_URL}/api/",
        "confidence": "High",
        "risk_score": 5.0,
        "description": "The API endpoint returns Access-Control-Allow-Origin: * for credentialled requests, allowing any origin to read HTTP responses.",
        "evidence": "Response header: Access-Control-Allow-Origin: *\nResponse header: Access-Control-Allow-Credentials: true",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "detected_by": "Nuclei",
        "remediation": "Restrict Access-Control-Allow-Origin to specific trusted origins. Do not use wildcard for authenticated endpoints.",
    },
    {
        "title": "Missing Content-Security-Policy Header",
        "vuln_type": "Security Header Missing",
        "severity": "Medium",
        "endpoint": DEMO_TARGET_URL,
        "confidence": "High",
        "risk_score": 4.0,
        "description": "The Content-Security-Policy header is absent from all HTTP responses, significantly increasing the risk of successful XSS attacks.",
        "evidence": "Template: csp-missing | Header 'Content-Security-Policy' not present in HTTP response",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "detected_by": "Nuclei",
        "remediation": "Add a Content-Security-Policy header to all HTTP responses defining trusted content sources.",
    },
    {
        "title": "Missing X-Frame-Options Header",
        "vuln_type": "Security Header Missing",
        "severity": "Low",
        "endpoint": DEMO_TARGET_URL,
        "confidence": "High",
        "risk_score": 1.5,
        "description": "The X-Frame-Options header is not set, allowing the site to be embedded in an iframe and potentially enabling clickjacking attacks.",
        "evidence": "Header 'X-Frame-Options' absent from HTTP response",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "detected_by": "Wapiti",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP responses.",
    },
    {
        "title": "Apache Version Disclosure",
        "vuln_type": "Information Disclosure",
        "severity": "Low",
        "endpoint": DEMO_TARGET_URL,
        "confidence": "High",
        "risk_score": 1.5,
        "description": "The Server HTTP header discloses the exact Apache version, helping attackers identify applicable CVEs.",
        "evidence": "Response header: Server: Apache/2.4.41 (Ubuntu)",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "detected_by": "Nuclei",
        "remediation": "Set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf to suppress version disclosure.",
    },
    {
        "title": "Backup File Publicly Accessible",
        "vuln_type": "Sensitive File Exposure",
        "severity": "Medium",
        "endpoint": f"{DEMO_TARGET_URL}/index.php.bak",
        "confidence": "High",
        "risk_score": 5.0,
        "description": "A database backup file is accessible at a predictable URL, potentially exposing credentials and application logic.",
        "evidence": "HTTP 200 OK returned for /index.php.bak — source code visible",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "detected_by": "Wapiti",
        "remediation": "Remove backup files from the web root. Configure the web server to deny access to .bak, .old, .tmp extensions.",
    },
    {
        "title": "Weak Session Management (No Secure Flag)",
        "vuln_type": "Broken Authentication",
        "severity": "Medium",
        "endpoint": f"{DEMO_TARGET_URL}/login.php",
        "confidence": "Medium",
        "risk_score": 4.5,
        "description": "Session cookies are issued without the Secure or HttpOnly flags, making them vulnerable to interception over HTTP and JavaScript-based theft.",
        "evidence": "Set-Cookie: PHPSESSID=abc123; path=/ (missing Secure and HttpOnly flags)",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "detected_by": "Wapiti, Nuclei",
        "remediation": "Set the Secure and HttpOnly flags on all session cookies. Ensure sessions are transmitted over HTTPS exclusively.",
    },
]


def make_hash(vuln_type: str, endpoint: str, title: str) -> str:
    raw = f"{vuln_type}||{endpoint}||{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def seed():
    init_db()
    db = SessionLocal()
    try:
        # ── 1. Upsert target ──────────────────────────────────────────────────
        target = db.query(models.Target).filter(
            models.Target.base_url == DEMO_TARGET_URL
        ).first()

        if not target:
            target = models.Target(
                name=DEMO_TARGET_NAME,
                base_url=DEMO_TARGET_URL,
                auth_required=False,
                notes="Demo target for presentation — Acunetix intentionally vulnerable PHP application.",
            )
            db.add(target)
            db.commit()
            db.refresh(target)
            print(f"[OK] Created target: {target.name} (id={target.id})")
        else:
            print(f"[OK] Target already exists (id={target.id})")

        # ── 2. Create a completed scan ────────────────────────────────────────
        now = datetime.datetime.utcnow()
        scan = models.Scan(
            target_id=target.id,
            scanner="wapiti+nuclei",
            status="completed",
            started_at=now - datetime.timedelta(minutes=4),
            completed_at=now - datetime.timedelta(minutes=1),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        print(f"[OK] Created scan (id={scan.id})")

        # ── 3. Insert demo vulnerabilities ────────────────────────────────────
        inserted = 0
        for v in DEMO_VULNS:
            vuln_hash = make_hash(v["vuln_type"], v["endpoint"], v["title"])
            exists = db.query(models.Vulnerability).filter(
                models.Vulnerability.vuln_hash == vuln_hash
            ).first()
            if exists:
                print(f"  – Skipped (duplicate): {v['title']}")
                continue

            vuln = models.Vulnerability(
                vuln_hash=vuln_hash,
                scan_id=scan.id,
                target_id=target.id,
                title=v["title"],
                vuln_type=v["vuln_type"],
                severity=v["severity"],
                endpoint=v["endpoint"],
                confidence=v["confidence"],
                risk_score=v["risk_score"],
                description=v["description"],
                evidence=v["evidence"],
                owasp_category=v["owasp_category"],
                detected_by=v["detected_by"],
                remediation=v["remediation"],
            )
            db.add(vuln)
            inserted += 1

        db.commit()
        print(f"\n[OK] Seeded {inserted} demo vulnerabilities into scan #{scan.id}")
        print(f"   Target: {DEMO_TARGET_NAME} ({DEMO_TARGET_URL})")
        print(f"   Open http://localhost:5173 to see the populated dashboard!")

    except Exception as e:
        db.rollback()
        import traceback
        with open("error.log", "w") as f:
            f.write(str(e) + "\n\n" + traceback.format_exc())
        print(f"[ERROR] Exception written to error.log")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
