"""
correlator.py — Vulnerability Correlation Engine.

Groups findings by (endpoint, vuln_type), merges duplicates from
multiple scanners, and boosts confidence when multiple scanners agree.
"""

from typing import List
from backend.normalization.normalizer import NormalizedVulnerability


CONFIDENCE_BOOST = {
    ("High", 1): "High",
    ("Medium", 1): "Medium",
    ("Low", 1): "Low",
    ("Low", 2): "Medium",    # 2 scanners → bump up
    ("Medium", 2): "High",
    ("High", 2): "High",
    ("Low", 3): "High",
    ("Medium", 3): "High",
    ("High", 3): "High",
}


def correlate(findings: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
    """
    Deduplicate and merge vulnerabilities from multiple scanners.

    Grouping key: normalized (endpoint_path, vuln_type).
    When multiple scanners detect the same issue:
      - Merge detected_by list
      - Keep the highest severity
      - Boost confidence score
      - Merge evidence and description
    """
    groups: dict[str, NormalizedVulnerability] = {}

    for finding in findings:
        key = _make_key(finding)
        if key not in groups:
            groups[key] = finding
        else:
            existing = groups[key]
            existing = _merge(existing, finding)
            groups[key] = existing

    results = list(groups.values())
    return results


def _make_key(f: NormalizedVulnerability) -> str:
    """Normalize endpoint to path only, strip query params for grouping."""
    from urllib.parse import urlparse
    try:
        path = urlparse(f.endpoint).path.rstrip("/") or "/"
    except Exception:
        path = f.endpoint

    # Normalize vuln type to lowercase for matching
    vuln_type = f.vuln_type.lower().strip()
    return f"{path}||{vuln_type}"


def _merge(base: NormalizedVulnerability, new: NormalizedVulnerability) -> NormalizedVulnerability:
    """Merge `new` into `base`, returning an updated base."""
    # Merge scanner names
    scanners = set(base.detected_by.split(", ")) | {new.detected_by}
    scanners.discard("")
    base.detected_by = ", ".join(sorted(scanners))

    # Keep highest severity
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    if sev_order.index(new.severity) < sev_order.index(base.severity):
        base.severity = new.severity

    # Boost confidence based on scanner count
    scanner_count = len(scanners)
    base.confidence = CONFIDENCE_BOOST.get(
        (base.confidence, min(scanner_count, 3)), base.confidence
    )

    # Merge evidence
    if new.evidence and new.evidence not in base.evidence:
        base.evidence = base.evidence + " | " + new.evidence if base.evidence else new.evidence

    # Merge description
    if new.description and new.description not in base.description:
        base.description = base.description + " " + new.description if base.description else new.description

    return base
