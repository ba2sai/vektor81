"""Pure-Python Panama Ley 81 / DE 285 PII detection, RUCTB DV, and masking package."""

from __future__ import annotations

from .detectors import PiiFinding, analyze_text
from .masking import hash_pii_sha256, mask_pii_value
from .presidio_adapter import (
    PRESIDIO_AVAILABLE,
    FallbackPanamaAnalyzer,
    PanamaCedulaRucRecognizer,
    PanamaPassportRecognizer,
    PanamaSensitiveHealthRecognizer,
    PresidioFallbackResult,
    build_panama_analyzer,
)
from .ructb import (
    calcular_dv_ructb,
    classify_panama_id,
    normalize_to_ructb,
    verify_ruc_dv,
)
from .validators import (
    CORPORATE_CONTEXT_ES,
    FINANCIAL_CONTEXT_ES,
    IDENTITY_CONTEXT_ES,
    PASSPORT_CONTEXT_ES,
    SENSITIVE_CONTEXT_ES,
    is_corporate_ruc,
    is_date_collision,
    is_valid_luhn,
    is_valid_panama_swift,
    normalize_context_text,
)

__version__ = "2.0.0"

__all__ = [
    "__version__",
    "CORPORATE_CONTEXT_ES",
    "FINANCIAL_CONTEXT_ES",
    "IDENTITY_CONTEXT_ES",
    "PASSPORT_CONTEXT_ES",
    "PRESIDIO_AVAILABLE",
    "SENSITIVE_CONTEXT_ES",
    "FallbackPanamaAnalyzer",
    "PanamaCedulaRucRecognizer",
    "PanamaPassportRecognizer",
    "PanamaSensitiveHealthRecognizer",
    "PiiFinding",
    "PresidioFallbackResult",
    "analyze_text",
    "build_panama_analyzer",
    "calcular_dv_ructb",
    "classify_panama_id",
    "hash_pii_sha256",
    "is_corporate_ruc",
    "is_date_collision",
    "is_valid_luhn",
    "is_valid_panama_swift",
    "mask_pii_value",
    "normalize_context_text",
    "normalize_to_ructb",
    "verify_ruc_dv",
]
