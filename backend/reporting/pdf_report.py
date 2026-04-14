"""
pdf_report.py — PDF report generator using WeasyPrint.

WeasyPrint converts HTML to PDF. Install: pip install weasyprint
On Windows you also need GTK runtime. If unavailable, PDF generation
is gracefully skipped and only HTML is offered.
"""

import logging

logger = logging.getLogger(__name__)


def generate_pdf_report(html_path: str, output_path: str):
    """Convert the HTML report to PDF using WeasyPrint."""
    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(output_path)
        logger.info(f"[Report] PDF generated: {output_path}")
    except ImportError:
        raise RuntimeError(
            "WeasyPrint is not installed. Run: pip install weasyprint\n"
            "On Windows, you also need the GTK runtime from: https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer"
        )
    except Exception as e:
        logger.error(f"[Report] PDF generation failed: {e}")
        raise
