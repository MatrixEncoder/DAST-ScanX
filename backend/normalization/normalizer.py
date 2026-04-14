"""
normalizer.py — Normalization layer that converts raw scanner findings
into a unified NormalizedVulnerability schema with OWASP Top 10 mapping.
"""

import uuid
from dataclasses import dataclass
from typing import List
from backend.scanners.base import RawFinding


# ─────────────────────────────────────────────────────────────
# OWASP Top 10 2021 Mapping
# ─────────────────────────────────────────────────────────────
OWASP_MAPPING = {
    "SQL Injection":              "A03:2021 – Injection",
    "Cross-Site Scripting":       "A03:2021 – Injection",
    "Command Injection":          "A03:2021 – Injection",
    "LDAP Injection":             "A03:2021 – Injection",
    "XML Injection":              "A03:2021 – Injection",
    "Path Traversal":             "A01:2021 – Broken Access Control",
    "Directory Traversal":        "A01:2021 – Broken Access Control",
    "IDOR":                       "A01:2021 – Broken Access Control",
    "Remote Code Execution":      "A08:2021 – Software and Data Integrity Failures",
    "Security Misconfiguration":  "A05:2021 – Security Misconfiguration",
    "CORS Misconfiguration":      "A05:2021 – Security Misconfiguration",
    "Security Header Missing":    "A05:2021 – Security Misconfiguration",
    "Sensitive File Exposure":    "A05:2021 – Security Misconfiguration",
    "Information Disclosure":     "A05:2021 – Security Misconfiguration",
    "Known CVE":                  "A06:2021 – Vulnerable and Outdated Components",
    "Broken Authentication":      "A07:2021 – Identification and Authentication Failures",
    "Weak Password":              "A07:2021 – Identification and Authentication Failures",
    "Security Issue":             "A05:2021 – Security Misconfiguration",
}


# ─────────────────────────────────────────────────────────────
# Remediation Advice
# ─────────────────────────────────────────────────────────────
REMEDIATION_MAP = {
    "SQL Injection": (
        "Use parameterized queries or prepared statements. "
        "Avoid constructing SQL queries with user-supplied input. "
        "Implement an ORM layer and apply input validation."
    ),
    "Cross-Site Scripting": (
        "Encode all user-supplied data before rendering in HTML. "
        "Implement a strict Content-Security-Policy header. "
        "Use framework-provided auto-escaping mechanisms."
    ),
    "Path Traversal": (
        "Validate and sanitize file path inputs. "
        "Use allowlists for permitted paths. "
        "Chroot the web server process or use a virtual filesystem."
    ),
    "Security Header Missing": (
        "Add the missing security headers to all HTTP responses: "
        "X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, "
        "Strict-Transport-Security, Referrer-Policy."
    ),
    "CORS Misconfiguration": (
        "Restrict Access-Control-Allow-Origin to specific trusted origins. "
        "Do not use wildcard (*) for authenticated endpoints. "
        "Validate the Origin header server-side."
    ),
    "Sensitive File Exposure": (
        "Remove backup files, sensitive configuration files, and debug files from the web root. "
        "Configure the web server to deny access to sensitive file extensions."
    ),
    "Remote Code Execution": (
        "Do not pass user-supplied input to shell functions. "
        "Apply strict input validation and allowlisting. "
        "Sandbox or containerize the application."
    ),
    "Security Misconfiguration": (
        "Follow security hardening checklists for the web server and framework. "
        "Disable directory listing, remove default credentials, and patch known vulnerabilities."
    ),
    "Known CVE": (
        "Update the affected software component to the latest patched version. "
        "Subscribe to vendor security advisories."
    ),
    "Information Disclosure": (
        "Remove version information from HTTP headers and error pages. "
        "Use custom error pages and suppress stack traces in production."
    ),
}

DEFAULT_REMEDIATION = (
    "Review the vulnerability details and apply appropriate security controls. "
    "Follow OWASP guidelines for the relevant vulnerability category."
)


@dataclass
class NormalizedVulnerability:
    vuln_uuid: str
    title: str
    vuln_type: str
    endpoint: str
    severity: str
    confidence: str
    description: str
    evidence: str
    owasp_category: str
    detected_by: str
    remediation: str
    risk_score: float = 0.0


def normalize(findings: List[RawFinding]) -> List[NormalizedVulnerability]:
    """
    Convert a list of RawFindings from any scanner into
    NormalizedVulnerability objects with OWASP category and remediation advice.
    """
    normalized = []
    for f in findings:
        owasp = _map_owasp(f.vuln_type) or _map_owasp(f.title)
        remediation = _get_remediation(f.vuln_type)

        normalized.append(NormalizedVulnerability(
            vuln_uuid=str(uuid.uuid4()),
            title=f.title,
            vuln_type=f.vuln_type,
            endpoint=f.endpoint,
            severity=_normalize_severity(f.severity),
            confidence=_normalize_confidence(f.confidence),
            description=f.description,
            evidence=f.evidence,
            owasp_category=owasp,
            detected_by=f.scanner_name,
            remediation=remediation,
        ))
    return normalized


def _map_owasp(text: str) -> str:
    text_lower = text.lower()
    for key, category in OWASP_MAPPING.items():
        if key.lower() in text_lower:
            return category
    return "A05:2021 – Security Misconfiguration"


def _get_remediation(vuln_type: str) -> str:
    for key, advice in REMEDIATION_MAP.items():
        if key.lower() in vuln_type.lower():
            return advice
    return DEFAULT_REMEDIATION


def _normalize_severity(raw: str) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "informational": "Info",
        "info": "Info",
        "none": "Info",
    }
    return mapping.get(raw.lower(), "Low")


def _normalize_confidence(raw: str) -> str:
    mapping = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "certain": "High",
        "firm": "Medium",
        "tentative": "Low",
    }
    return mapping.get(raw.lower(), "Low")
