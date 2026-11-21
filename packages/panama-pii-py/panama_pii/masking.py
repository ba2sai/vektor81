"""Data minimization masking and SHA-256 hashing helpers for Panama Ley 81 compliance."""

from __future__ import annotations

import hashlib
import re

_CARD_LIKE_RE = re.compile(r"^\d{13,19}$")


def mask_pii_value(val: str) -> str:
    """Mask sensitive values so raw PII is never persisted in logs or telemetry."""
    if not isinstance(val, str):
        return "***"
    cleaned = val.strip()
    if not cleaned:
        return "***"
    if "@" in cleaned and cleaned.count("@") == 1:
        local, domain = cleaned.split("@", 1)
        prefix = local[:2] if len(local) > 2 else local[:1]
        return f"{prefix}***@{domain}"
    compact_digits = re.sub(r"[\s-]+", "", cleaned)
    if _CARD_LIKE_RE.fullmatch(compact_digits) and re.fullmatch(r"[\d\s-]+", cleaned):
        return f"{compact_digits[:4]}{'*' * (len(compact_digits) - 8)}{compact_digits[-4:]}"
    if len(cleaned) <= 4:
        return "***"
    if len(cleaned) <= 7:
        return f"{cleaned[:2]}***{cleaned[-1:]}"
    return f"{cleaned[:3]}***{cleaned[-2:]}"


def hash_pii_sha256(val: str) -> str:
    """Return deterministic lowercase SHA-256 hex digest of a PII token."""
    cleaned = val.strip() if isinstance(val, str) else str(val)
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
