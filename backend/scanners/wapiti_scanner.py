"""
wapiti_scanner.py — Wapiti DAST scanner integration.

Runs wapiti via subprocess, parses JSON output into RawFindings.
Install: pip install wapiti3
"""

import os
import json
import logging
import subprocess
import tempfile
from typing import List

from backend.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger(__name__)

# Map Wapiti severity strings to normalized levels
WAPITI_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
    "info": "Info",
    "0": "Info",
    "1": "Low",
    "2": "Medium",
    "3": "High",
}


import sys


# Try 'wapiti' from PATH first, then fall back to known install locations
def _find_wapiti():
    import sys, os
    scripts_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
    candidates = [
        ["wapiti", "--version"],
        [os.path.join(scripts_dir, "wapiti.exe"), "--version"],
        [os.path.join(scripts_dir, "wapiti.EXE"), "--version"],
        [sys.executable, "-m", "wapiti", "--version"],
    ]
    for cmd in candidates:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=10)
            if r.returncode == 0:
                return cmd[:-1]  # return command without --version flag
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    return None


class WapitiScanner(BaseScanner):
    name = "Wapiti"

    def _exe(self):
        return _find_wapiti()

    def is_available(self) -> bool:
        return self._exe() is not None

    def scan(self, target_url: str, endpoints: List[str]) -> List[RawFinding]:
        exe = self._exe()
        logger.info(f"[Wapiti] Scanning {target_url} using {exe}")
        findings = []

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "wapiti_output.json")
            cmd = exe + [
                "-u", target_url,
                "-f", "json",
                "-o", output_file,
                "--flush-session",
                "-m", "sql,xss,file,htaccess,backup,nikto,shellshock,methods,headers,cors",
                "--scope", "url",
                "--timeout", "10",
                "--max-scan-time", "120",
                "--color",
            ]

            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                if os.path.exists(output_file):
                    findings = self._parse_output(output_file, target_url)
                else:
                    logger.warning("[Wapiti] No output file generated")
            except subprocess.TimeoutExpired:
                logger.warning("[Wapiti] Scan timed out")
            except Exception as e:
                logger.error(f"[Wapiti] Error: {e}")

        logger.info(f"[Wapiti] Found {len(findings)} findings")
        return findings

    def _parse_output(self, output_file: str, target_url: str) -> List[RawFinding]:
        findings = []
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            vulnerabilities = data.get("vulnerabilities", {})
            for vuln_type, vuln_list in vulnerabilities.items():
                if not isinstance(vuln_list, list):
                    continue
                for item in vuln_list:
                    path = item.get("path", "") or item.get("url", "")
                    parameter = item.get("parameter", "")
                    info = item.get("info", "")
                    level = str(item.get("level", "1"))
                    severity = WAPITI_SEVERITY_MAP.get(level, "Low")

                    endpoint = path if path.startswith("http") else target_url.rstrip("/") + path

                    findings.append(RawFinding(
                        title=f"{vuln_type} detected",
                        vuln_type=vuln_type,
                        endpoint=endpoint,
                        severity=severity,
                        description=info,
                        evidence=f"Parameter: {parameter}" if parameter else "",
                        confidence="Medium",
                        scanner_name=self.name,
                    ))
        except Exception as e:
            logger.error(f"[Wapiti] Failed to parse output: {e}")
        return findings


# Fake findings removed to avoid misleading users during live scans.
