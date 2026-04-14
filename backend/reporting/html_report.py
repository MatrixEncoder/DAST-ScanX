"""
html_report.py — Jinja2-based HTML security report generator.
"""

import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


def generate_html_report(scan, target, vulnerabilities: list, output_path: str):
    """Render and save an HTML security report."""
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template("report.html")

    severity_counts = {
        "Critical": sum(1 for v in vulnerabilities if v.severity == "Critical"),
        "High":     sum(1 for v in vulnerabilities if v.severity == "High"),
        "Medium":   sum(1 for v in vulnerabilities if v.severity == "Medium"),
        "Low":      sum(1 for v in vulnerabilities if v.severity == "Low"),
        "Info":     sum(1 for v in vulnerabilities if v.severity == "Info"),
    }

    context = {
        "scan": scan,
        "target": target,
        "vulnerabilities": vulnerabilities,
        "severity_counts": severity_counts,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total": len(vulnerabilities),
    }

    html = template.render(**context)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
