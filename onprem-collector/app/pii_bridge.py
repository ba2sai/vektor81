"""Bridge between onprem-collector and packages/panama-pii-py (Ley 81 / DE 285 PII engine)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any


def _ensure_panama_pii_on_path() -> None:
    """Add local packages/panama-pii-py to sys.path when not pip-installed."""
    try:
        import panama_pii  # noqa: F401
        return
    except ImportError:
        pass

    current = Path(__file__).resolve()
    candidates = [
        current.parents[2] / "packages" / "panama-pii-py",
        Path("/app/packages/panama-pii-py"),
    ]
    env_path = os.getenv("PANAMA_PII_PACKAGE_PATH")
    if env_path:
        candidates.insert(0, Path(env_path))

    for candidate in candidates:
        if candidate.is_dir():
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)
            break


_ensure_panama_pii_on_path()

from panama_pii import (  # noqa: E402
    PRESIDIO_AVAILABLE,
    PiiFinding,
    analyze_text,
    build_panama_analyzer,
    calcular_dv_ructb,
    classify_panama_id,
    hash_pii_sha256,
    mask_pii_value,
    verify_ruc_dv,
)

RETENTION_LIMIT_GENERAL_DAYS = 2555  # 7 years (365 * 7) for ANTAI_LEY81 / SBP_001_2022
RETENTION_LIMIT_SALUD_CLINICAL_DAYS = 7300  # 20 years (365 * 20) post-mortem under Ley 68 de 2003


def evaluate_retention_violation(
    regulatory_profile: str,
    age_days: int | None,
    is_clinical: bool = False,
) -> bool:
    """
    Evaluate document/record retention compliance against the tenant's regulatory profile.

    - ANTAI_LEY81 / SBP_001_2022: records older than 7 years (2555 days) trigger retention violation.
    - SALUD_LEY68: clinical records (< 20 years / 7300 days) are protected mandatory retention
      (NOT violations); non-clinical administrative records > 7 years ARE flagged.
    """
    if age_days is None or age_days < 0:
        return False

    profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
    if profile == "SALUD_LEY68":
        if is_clinical:
            return age_days >= RETENTION_LIMIT_SALUD_CLINICAL_DAYS
        return age_days > RETENTION_LIMIT_GENERAL_DAYS

    return age_days > RETENTION_LIMIT_GENERAL_DAYS


def compute_finding_severity(
    entity_type: str,
    is_sensitive: bool,
    retention_violation: bool = False,
) -> str:
    """Map finding attributes to shared-contracts AlertSeverity."""
    if is_sensitive or entity_type in ("PA_DATO_SENSIBLE_SALUD", "PA_TARJETA_PAGO"):
        return "CRITICAL"
    if retention_violation or entity_type in ("PA_IDENTIDAD_NATURAL", "PA_PASAPORTE", "PA_SWIFT_PA"):
        return "HIGH"
    return "MEDIUM"


def get_pii_engine_status() -> dict[str, Any]:
    """Inspect active PII engine capabilities without failing on missing NLP extras."""
    spacy_model: str | None = None
    if PRESIDIO_AVAILABLE:
        try:
            import spacy  # type: ignore[import-untyped]

            for model_name in ("es_core_news_lg", "es_core_news_md", "es_core_news_sm"):
                if spacy.util.is_package(model_name):
                    spacy_model = model_name
                    break
        except Exception:
            spacy_model = None

    return {
        "engine": "panama-pii-py",
        "presidio_available": bool(PRESIDIO_AVAILABLE),
        "spacy_model": spacy_model,
        "deterministic_fallback_active": True,
    }


__all__ = [
    "PRESIDIO_AVAILABLE",
    "PiiFinding",
    "RETENTION_LIMIT_GENERAL_DAYS",
    "RETENTION_LIMIT_SALUD_CLINICAL_DAYS",
    "analyze_text",
    "build_panama_analyzer",
    "calcular_dv_ructb",
    "classify_panama_id",
    "compute_finding_severity",
    "evaluate_retention_violation",
    "get_pii_engine_status",
    "hash_pii_sha256",
    "mask_pii_value",
    "verify_ruc_dv",
]
