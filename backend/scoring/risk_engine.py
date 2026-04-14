"""
risk_engine.py — Risk Scoring Engine.

Computes a composite risk score for each vulnerability.

Formula:
  Risk Score = Severity Weight + Confidence Weight + Exposure Bonus

  Severity weights:
    Critical = 9.0
    High     = 7.0
    Medium   = 4.0
    Low      = 1.5
    Info     = 0.5

  Confidence multipliers:
    High   × 1.0
    Medium × 0.8
    Low    × 0.6

  Exposure bonus (if endpoint is /api/ or auth-related):
    +1.0 bonus

Score is rounded to 2 decimal places, max 10.0.
"""

from typing import List
from backend.normalization.normalizer import NormalizedVulnerability


SEVERITY_WEIGHT = {
    "Critical": 9.0,
    "High":     7.0,
    "Medium":   4.0,
    "Low":      1.5,
    "Info":     0.5,
}

CONFIDENCE_MULTIPLIER = {
    "High":   1.0,
    "Medium": 0.8,
    "Low":    0.6,
}

EXPOSURE_KEYWORDS = [
    "admin", "login", "auth", "api", "user",
    "account", "password", "token", "session", "reset",
]


def score_vulnerabilities(findings: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
    """
    Calculate and assign risk scores to each vulnerability.
    Returns findings sorted by score descending.
    """
    for finding in findings:
        finding.risk_score = _calculate_score(finding)

    findings.sort(key=lambda v: v.risk_score, reverse=True)
    return findings


def _calculate_score(v: NormalizedVulnerability) -> float:
    sev = SEVERITY_WEIGHT.get(v.severity, 1.5)
    conf = CONFIDENCE_MULTIPLIER.get(v.confidence, 0.6)
    exposure = _exposure_bonus(v.endpoint)

    score = float((sev * conf) + exposure)
    return float(round(min(score, 10.0), 2))


def _exposure_bonus(endpoint: str) -> float:
    endpoint_lower = endpoint.lower()
    for keyword in EXPOSURE_KEYWORDS:
        if keyword in endpoint_lower:
            return 1.0
    return 0.0
