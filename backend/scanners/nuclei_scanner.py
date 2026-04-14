"""
nuclei_scanner.py — Nuclei DAST scanner integration.

Runs nuclei via subprocess, parses JSONL output into RawFindings.
Install: https://github.com/projectdiscovery/nuclei/releases
"""

import os
import json
import logging
import subprocess
import tempfile
from typing import List

from backend.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger(__name__)

NUCLEI_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Low",
}


def _build_nuclei_candidates():
    """Build list of nuclei executable paths to try."""
    import shutil
    candidates = []
    # 1. PATH-based (works if already in PATH)
    which = shutil.which("nuclei")
    if which:
        candidates.append(which)
    # 2. Common Windows install locations
    home = os.path.expanduser("~")
    candidates += [
        r"C:\Scan-X\nuclei.exe",
        r"C:\Scan-X\nuclei",
        os.path.join(home, "go", "bin", "nuclei.exe"),
        os.path.join(home, "AppData", "Roaming", "nuclei", "nuclei.exe"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "nuclei.exe"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "nuclei"),
    ]
    return candidates


def _find_nuclei() -> str | None:
    """Return the first nuclei executable that exists and responds."""
    for candidate in _build_nuclei_candidates():
        if not os.path.isfile(candidate) and candidate not in ("nuclei",):
            continue
        try:
            r = subprocess.run([candidate, "-version"], capture_output=True, timeout=10)
            if r.returncode == 0:
                return candidate
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    return None


class NucleiScanner(BaseScanner):
    name = "Nuclei"

    def _exe(self) -> str | None:
        return _find_nuclei()

    def is_available(self) -> bool:
        return self._exe() is not None

    def scan(self, target_url: str, endpoints: List[str]) -> List[RawFinding]:
        exe = self._exe()
        logger.info(f"[Nuclei] Scanning {target_url} using {exe}")
        findings = []

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "nuclei_output.jsonl")
            cmd = [
                exe,
                "-u", target_url,
                "-json-export", output_file,
                "-silent",
                "-severity", "critical,high,medium,low,info",
                "-timeout", "10",
                "-t", "http/vulnerabilities,http/misconfiguration,http/exposures,http/technologies",
                "-stats",
            ]

            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if os.path.exists(output_file):
                    findings = self._parse_output(output_file)
                else:
                    logger.warning("[Nuclei] No output file generated")
            except subprocess.TimeoutExpired:
                logger.warning("[Nuclei] Scan timed out")
            except Exception as e:
                logger.error(f"[Nuclei] Error: {e}")

        logger.info(f"[Nuclei] Found {len(findings)} findings")
        return findings

    def _parse_output(self, output_file: str) -> List[RawFinding]:
        findings = []
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        severity_raw = item.get("info", {}).get("severity", "info")
                        severity = NUCLEI_SEVERITY_MAP.get(severity_raw.lower(), "Low")
                        name = item.get("info", {}).get("name", "Unknown")
                        template_id = item.get("template-id", "")
                        matched_at = item.get("matched-at", "")
                        description = item.get("info", {}).get("description", "")
                        reference = ", ".join(item.get("info", {}).get("reference", []))

                        findings.append(RawFinding(
                            title=name,
                            vuln_type=_map_nuclei_type(template_id, name),
                            endpoint=matched_at,
                            severity=severity,
                            description=description,
                            evidence=f"Template: {template_id}" + (f" | Ref: {reference}" if reference else ""),
                            confidence="High" if severity in ("Critical", "High") else "Medium",
                            scanner_name=self.name,
                        ))
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"[Nuclei] Failed to parse output: {e}")
        return findings


def _map_nuclei_type(template_id: str, name: str) -> str:
    template_lower = template_id.lower()
    name_lower = name.lower()
    if "sqli" in template_lower or "sql" in name_lower:
        return "SQL Injection"
    if "xss" in template_lower or "cross-site" in name_lower:
        return "Cross-Site Scripting"
    if "lfi" in template_lower or "path-traversal" in template_lower:
        return "Path Traversal"
    if "rce" in template_lower or "remote-code" in name_lower:
        return "Remote Code Execution"
    if "misconfig" in template_lower or "misconfiguration" in name_lower:
        return "Security Misconfiguration"
    if "exposure" in template_lower or "sensitive" in name_lower:
        return "Sensitive File Exposure"
    if "header" in template_lower:
        return "Security Header Missing"
    if "cors" in template_lower:
        return "CORS Misconfiguration"
    if "cve" in template_lower:
        return "Known CVE"
    return "Security Issue"


# Fake findings removed to avoid misleading users during live scans.
