"""Pure-stdlib validators and normalized Spanish context lexicons for Panama PII."""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Sequence

_DV_SUFFIX_RE = re.compile(r"\s+DV\s*(\d{1,2})$", re.IGNORECASE)
_SWIFT_PA_RE = re.compile(r"^[A-Z]{4}PA[A-Z0-9]{2}(?:[A-Z0-9]{3})?$")

HEALTH_SENSITIVE_TERMS: tuple[str, ...] = (
    "vih",
    "hiv",
    "sida",
    "diagnostico",
    "historia clinica",
    "expediente clinico",
    "historial medico",
    "paciente",
    "hospital",
    "clinica",
    "css",
    "caja de seguro social",
    "minsa",
    "patologia",
    "enfermedad",
    "tratamiento medico",
    "receta medica",
    "incapacidad medica",
    "psiquiatria",
    "oncologia",
    "cancer",
    "diabetes",
    "salud mental",
    "examen medico",
    "laboratorio clinico",
    "grupo sanguineo",
    "tipo de sangre",
    "datos geneticos",
    "adn",
    "discapacidad",
)

PATIENT_IDENTITY_TERMS: tuple[str, ...] = (
    "paciente",
    "cedula",
    "cip",
    "c.i.p.",
    "portador",
    "portadora",
    "titular",
    "asegurado",
    "asegurada",
    "historia clinica",
    "expediente clinico",
    "expediente",
    "nombre",
    "persona",
    "colaborador",
    "empleado",
    "empleada",
)

SENSITIVE_CONTEXT_ES: tuple[str, ...] = HEALTH_SENSITIVE_TERMS + (
    "biometrica",
    "biometrico",
    "biometria",
    "huella",
    "huella dactilar",
    "huella biometrica",
    "reconocimiento facial",
    "iris",
    "sindicato",
    "sindical",
    "afiliado al sindicato",
    "religion",
    "religioso",
    "creencia religiosa",
    "orientacion sexual",
    "preferencia sexual",
    "origen etnico",
    "origen racial",
    "opinion politica",
    "afiliacion politica",
    "partido politico",
    "antecedentes penales",
)

CORPORATE_CONTEXT_ES: tuple[str, ...] = (
    "sociedad anonima",
    "s.a.",
    "s. a.",
    "s.r.l.",
    "srl",
    "corp.",
    "inc.",
    "llc",
    "ltda",
    "registro publico",
    "folio mercantil",
    "ficha",
    "rollo",
    "imagen",
    "factura",
    "factura fiscal",
    "proveedor",
    "proveedores",
    "persona juridica",
    "razon social",
    "empresa",
    "compania",
    "inversiones",
    "comercial",
    "corporacion",
    "b2b",
    "ruc juridico",
    "aviso de operacion",
    "orden de compra",
)

PASSPORT_CONTEXT_ES: tuple[str, ...] = (
    "pasaporte",
    "apap",
    "autoridad de pasaportes",
    "passport",
    "viajero",
    "viajera",
    "migracion",
    "servicio nacional de migracion",
    "salvoconducto",
    "visado",
    "visa",
)

FINANCIAL_CONTEXT_ES: tuple[str, ...] = (
    "swift",
    "bic",
    "ach",
    "iban",
    "transferencia",
    "banco",
    "bancaria",
    "bancario",
    "entidad bancaria",
    "cuenta",
    "cuenta de ahorros",
    "cuenta corriente",
    "giro",
    "remesa",
    "deposito",
    "tarjeta",
    "tarjeta de credito",
    "tarjeta de debito",
    "tarjeta corporativa",
    "visa",
    "mastercard",
    "amex",
    "pago",
    "sbp",
    "superintendencia de bancos",
)

IDENTITY_CONTEXT_ES: tuple[str, ...] = (
    "cedula",
    "cip",
    "c.i.p.",
    "portador",
    "portadora",
    "identidad personal",
    "documento de identidad",
    "tarjeta de identidad",
    "identificacion personal",
    "numero de identidad",
    "persona natural",
    "tribunal electoral",
)


def normalize_context_text(text: str) -> str:
    """Return lowercase ASCII-folded text with combining diacritics removed."""
    if not text:
        return ""
    decomposed = unicodedata.normalize("NFD", text)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return stripped.lower()


def _normalize_with_index_map(text: str) -> tuple[str, list[int]]:
    """Normalize text while keeping a 1:1 map back to original character offsets."""
    norm_chars: list[str] = []
    index_map: list[int] = []
    for idx, ch in enumerate(text):
        for part in unicodedata.normalize("NFD", ch):
            if unicodedata.category(part) != "Mn":
                norm_chars.append(part.lower())
                index_map.append(idx)
    return "".join(norm_chars), index_map


@lru_cache(maxsize=32)
def _compile_keyword_pattern(keywords: tuple[str, ...]) -> re.Pattern[str]:
    ordered = sorted({normalize_context_text(kw) for kw in keywords if kw}, key=len, reverse=True)
    alternation = "|".join(re.escape(kw) for kw in ordered)
    return re.compile(rf"(?<![a-z0-9])(?:{alternation})(?![a-z0-9])")


def find_context_matches(text: str, keywords: Sequence[str]) -> list[str]:
    """Return unique normalized context keywords matched in text, in order of appearance."""
    if not text or not keywords:
        return []
    norm_text = normalize_context_text(text)
    pattern = _compile_keyword_pattern(tuple(keywords))
    seen: dict[str, None] = {}
    for match in pattern.finditer(norm_text):
        seen.setdefault(match.group(0), None)
    return list(seen.keys())


def find_context_spans(text: str, keywords: Sequence[str]) -> list[tuple[int, int, str]]:
    """Return (start, end, normalized_keyword) spans in original text coordinates."""
    if not text or not keywords:
        return []
    norm_text, index_map = _normalize_with_index_map(text)
    if not norm_text:
        return []
    pattern = _compile_keyword_pattern(tuple(keywords))
    results: list[tuple[int, int, str]] = []
    text_len = len(text)
    for match in pattern.finditer(norm_text):
        start = index_map[match.start()]
        end = index_map[match.end() - 1] + 1
        while end < text_len and unicodedata.category(text[end]) == "Mn":
            end += 1
        results.append((start, end, match.group(0)))
    return results


def strip_dv_suffix(token: str) -> tuple[str, str | None]:
    """Strip an optional trailing 'DV NN' suffix and return (core, dv_or_none)."""
    cleaned = token.strip()
    match = _DV_SUFFIX_RE.search(cleaned)
    if not match:
        return cleaned, None
    return cleaned[: match.start()].strip(), match.group(1)


def is_date_collision(token: str) -> bool:
    """Return True if token matches DD-MM-YYYY, D-MM-YYYY, or YYYY-MM-DD date patterns."""
    if not isinstance(token, str):
        return False
    cleaned = token.strip()
    if not cleaned or " " in cleaned:
        return False
    parts = cleaned.split("-")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return False
    p0, p1, p2 = parts
    if (
        len(p0) in (1, 2)
        and len(p1) == 2
        and len(p2) == 4
        and 1 <= int(p0) <= 31
        and 1 <= int(p1) <= 12
        and 1900 <= int(p2) <= 2099
    ):
        return True
    if (
        len(p0) == 4
        and len(p1) == 2
        and len(p2) in (1, 2)
        and 1900 <= int(p0) <= 2099
        and 1 <= int(p1) <= 12
        and 1 <= int(p2) <= 31
    ):
        return True
    return False


def is_corporate_ruc(token: str) -> bool:
    """Return True if token matches a corporate/juridica RUC or folio mercantil."""
    if not isinstance(token, str):
        return False
    cleaned = token.strip().upper()
    if not cleaned:
        return False
    core, _ = strip_dv_suffix(cleaned)
    if is_date_collision(core):
        return False
    parts = core.split("-")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return False
    p0, p1, p2 = parts
    if p0.startswith("0") or not (1 <= len(p1) <= 8 and 1 <= len(p2) <= 8):
        return False
    return int(p0) > 13


def is_valid_luhn(number: str) -> bool:
    """Validate 13-19 digit payment card candidate using the Luhn mod-10 algorithm."""
    if not isinstance(number, str):
        return False
    digits = re.sub(r"[\s-]+", "", number.strip())
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    if set(digits) == {"0"}:
        return False
    total = 0
    for idx, ch in enumerate(digits[::-1]):
        val = int(ch)
        if idx % 2 == 1:
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return total % 10 == 0


def is_valid_panama_swift(code: str) -> bool:
    """Validate 8- or 11-character SWIFT/BIC code with Panama ISO country code 'PA' at [4:6]."""
    if not isinstance(code, str):
        return False
    cleaned = code.strip().upper()
    return bool(_SWIFT_PA_RE.fullmatch(cleaned))
