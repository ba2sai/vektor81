"""Deterministic Ley 81 / SBP / Ley 68 risk evaluation, PDF/HTML reports, and Ficha Técnica JSON."""

from .report_generator import (
    REPORT_HTML_TEMPLATE,
    WEASYPRINT_AVAILABLE,
    calculate_ley81_risk_score,
    generate_executive_pdf_bytes,
    generate_ficha_tecnica_json,
    get_regulatory_context,
    render_executive_html,
)

__all__ = [
    "REPORT_HTML_TEMPLATE",
    "WEASYPRINT_AVAILABLE",
    "calculate_ley81_risk_score",
    "generate_executive_pdf_bytes",
    "generate_ficha_tecnica_json",
    "get_regulatory_context",
    "render_executive_html",
]
