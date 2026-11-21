"""Contextual pure-stdlib Panama Ley 81 / DE 285 PII detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .masking import hash_pii_sha256, mask_pii_value
from .ructb import NATURAL_CLASSIFICATIONS, classify_panama_id
from .validators import (
    CORPORATE_CONTEXT_ES,
    FINANCIAL_CONTEXT_ES,
    HEALTH_SENSITIVE_TERMS,
    IDENTITY_CONTEXT_ES,
    PASSPORT_CONTEXT_ES,
    PATIENT_IDENTITY_TERMS,
    SENSITIVE_CONTEXT_ES,
    find_context_matches,
    find_context_spans,
    is_valid_luhn,
    is_valid_panama_swift,
)

_NATURAL_ID_RE = re.compile(
    r"(?<![A-Za-z0-9-])("
    r"(?:1[0-3]|[1-9])(?:AV|PI)-\d{1,4}-\d{1,6}"
    r"|(?:1[0-3]|[1-9])-NT-\d{1,4}-\d{1,6}"
    r"|(?:PE|E|N)-\d{1,4}-\d{1,6}"
    r"|(?:1[0-3]|[1-9])-\d{1,4}-\d{1,6}"
    r")(?:\s+DV\s*\d{1,2})?(?![A-Za-z0-9-])",
    re.IGNORECASE,
)

_PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9-])(PA\d{7}|[A-Z]{1,2}\d{6,8})(?![A-Za-z0-9-])")
_SWIFT_PA_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9-])([A-Z]{4}PA[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(?![A-Za-z0-9-])"
)
_CARD_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z-])("
    r"\d{13,19}"
    r"|(?:\d{4}[ -]){3}\d{3,4}(?:[ -]\d{1,3})?"
    r"|\d{4}[ -]\d{6}[ -]\d{5}"
    r")(?![0-9A-Za-z-])"
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9._%+-])"
)

_CLINICAL_TERMS: tuple[str, ...] = tuple(
    term for term in HEALTH_SENSITIVE_TERMS if term != "paciente"
)

_HIGH_PRIORITY_CLINICAL: frozenset[str] = frozenset(
    {
        "vih",
        "hiv",
        "sida",
        "cancer",
        "oncologia",
        "psiquiatria",
        "diabetes",
        "salud mental",
        "datos geneticos",
        "adn",
        "historia clinica",
        "expediente clinico",
        "historial medico",
        "diagnostico",
        "patologia",
    }
)


@dataclass
class PiiFinding:
    """Single masked PII finding compliant with Ley 81 minimization."""

    entity_type: str
    masked_value: str
    value_sha256: str
    score: float
    is_sensitive: bool
    start: int
    end: int
    context_matched: list[str] = field(default_factory=list)


def _window(text: str, start: int, end: int, before: int, after: int) -> str:
    left = max(0, start - before)
    right = min(len(text), end + after)
    return text[left:right]


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _detect_natural_ids(text: str, profile: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    for match in _NATURAL_ID_RE.finditer(text):
        token = match.group(1)
        start, end = match.span(1)
        kind = classify_panama_id(token)
        if kind not in NATURAL_CLASSIFICATIONS:
            continue

        corp_win = _window(text, start, end, 150, 150)
        id_win = _window(text, start, end, 90, 25)
        sens_win = _window(text, start, end, 160, 160)

        corp_hits = find_context_matches(corp_win, CORPORATE_CONTEXT_ES)
        id_hits = find_context_matches(id_win, IDENTITY_CONTEXT_ES)

        # Veto candidate when corporate context appears without explicit identity context.
        if corp_hits and not id_hits:
            continue

        sens_hits = find_context_matches(sens_win, SENSITIVE_CONTEXT_ES)
        score = 0.90 if id_hits else 0.75
        is_sensitive = bool(sens_hits)

        if is_sensitive:
            score = max(score, 0.97)
            if profile == "SALUD_LEY68" and any(h in HEALTH_SENSITIVE_TERMS for h in sens_hits):
                score = 0.99

        findings.append(
            PiiFinding(
                entity_type="PA_IDENTIDAD_NATURAL",
                masked_value=mask_pii_value(token),
                value_sha256=hash_pii_sha256(token),
                score=score,
                is_sensitive=is_sensitive,
                start=start,
                end=end,
                context_matched=_dedupe_preserve_order(id_hits + sens_hits),
            )
        )
    return findings


def _detect_passports(text: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    for match in _PASSPORT_RE.finditer(text):
        token = match.group(1)
        start, end = match.span(1)
        win = _window(text, start, end, 120, 120)
        pass_hits = find_context_matches(win, PASSPORT_CONTEXT_ES)
        if not pass_hits:
            continue

        sens_hits = find_context_matches(win, SENSITIVE_CONTEXT_ES)
        score = 0.92 if token.startswith("PA") else 0.85
        is_sensitive = bool(sens_hits)
        if is_sensitive:
            score = max(score, 0.96)

        findings.append(
            PiiFinding(
                entity_type="PA_PASAPORTE",
                masked_value=mask_pii_value(token),
                value_sha256=hash_pii_sha256(token),
                score=score,
                is_sensitive=is_sensitive,
                start=start,
                end=end,
                context_matched=_dedupe_preserve_order(pass_hits + sens_hits),
            )
        )
    return findings


def _detect_swift_pa(text: str, profile: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    for match in _SWIFT_PA_CANDIDATE_RE.finditer(text):
        token = match.group(1)
        start, end = match.span(1)
        if not is_valid_panama_swift(token):
            continue
        win = _window(text, start, end, 120, 120)
        fin_hits = find_context_matches(win, FINANCIAL_CONTEXT_ES)
        if not fin_hits:
            continue

        score = 0.95 if profile == "SBP_001_2022" else 0.90
        findings.append(
            PiiFinding(
                entity_type="PA_SWIFT_PA",
                masked_value=mask_pii_value(token),
                value_sha256=hash_pii_sha256(token),
                score=score,
                is_sensitive=False,
                start=start,
                end=end,
                context_matched=fin_hits,
            )
        )
    return findings


def _detect_payment_cards(text: str, profile: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    for match in _CARD_CANDIDATE_RE.finditer(text):
        token = match.group(1)
        start, end = match.span(1)
        if not is_valid_luhn(token):
            continue
        win = _window(text, start, end, 120, 120)
        fin_hits = find_context_matches(win, FINANCIAL_CONTEXT_ES)
        score = 0.92 if fin_hits else 0.80
        if profile == "SBP_001_2022":
            score = min(0.99, round(score + 0.04, 2))
        findings.append(
            PiiFinding(
                entity_type="PA_TARJETA_PAGO",
                masked_value=mask_pii_value(token),
                value_sha256=hash_pii_sha256(token),
                score=score,
                is_sensitive=False,
                start=start,
                end=end,
                context_matched=fin_hits,
            )
        )
    return findings


def _detect_emails(text: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    for match in _EMAIL_RE.finditer(text):
        token = match.group(1)
        start, end = match.span(1)
        win = _window(text, start, end, 120, 120)
        sens_hits = find_context_matches(win, SENSITIVE_CONTEXT_ES)
        is_sensitive = bool(sens_hits)
        score = 0.95 if is_sensitive else 0.85
        findings.append(
            PiiFinding(
                entity_type="EMAIL_PERSONAL",
                masked_value=mask_pii_value(token),
                value_sha256=hash_pii_sha256(token),
                score=score,
                is_sensitive=is_sensitive,
                start=start,
                end=end,
                context_matched=sens_hits,
            )
        )
    return findings


def _detect_sensitive_health(
    text: str,
    profile: str,
    natural_findings: list[PiiFinding],
) -> list[PiiFinding]:
    clinical_spans = find_context_spans(text, _CLINICAL_TERMS)
    if not clinical_spans:
        return []

    clusters: list[list[tuple[int, int, str]]] = []
    for span in clinical_spans:
        if not clusters or span[0] - clusters[-1][-1][1] > 200:
            clusters.append([span])
        else:
            clusters[-1].append(span)

    findings: list[PiiFinding] = []
    for cluster in clusters:
        c_start = cluster[0][0]
        c_end = cluster[-1][1]
        win_start = max(0, c_start - 160)
        win_end = min(len(text), c_end + 160)
        win = text[win_start:win_end]

        patient_hits = find_context_matches(win, PATIENT_IDENTITY_TERMS)
        has_local_nat_id = any(
            not (nf.end <= win_start or nf.start >= win_end) for nf in natural_findings
        )
        if not has_local_nat_id and not patient_hits:
            continue

        anchor = next(
            (sp for sp in cluster if sp[2] in _HIGH_PRIORITY_CLINICAL),
            cluster[0],
        )
        raw_token = text[anchor[0] : anchor[1]]
        score = 0.95 if has_local_nat_id else 0.90
        if profile == "SALUD_LEY68":
            score = 0.99 if has_local_nat_id else 0.98

        context_hits = _dedupe_preserve_order([sp[2] for sp in cluster] + patient_hits)
        findings.append(
            PiiFinding(
                entity_type="PA_DATO_SENSIBLE_SALUD",
                masked_value=mask_pii_value(raw_token),
                value_sha256=hash_pii_sha256(raw_token),
                score=score,
                is_sensitive=True,
                start=anchor[0],
                end=anchor[1],
                context_matched=context_hits,
            )
        )
    return findings


def analyze_text(text: str, regulatory_profile: str = "ANTAI_LEY81") -> list[PiiFinding]:
    """Analyze text for Panama Ley 81 / DE 285 PII entities with contextual disambiguation."""
    if not text or not isinstance(text, str):
        return []
    profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()

    natural_findings = _detect_natural_ids(text, profile)
    findings: list[PiiFinding] = [
        *natural_findings,
        *_detect_passports(text),
        *_detect_swift_pa(text, profile),
        *_detect_payment_cards(text, profile),
        *_detect_emails(text),
        *_detect_sensitive_health(text, profile, natural_findings),
    ]
    findings.sort(key=lambda item: (item.start, item.end, item.entity_type))
    return findings
