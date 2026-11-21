"""Panama DGI RUCTB 20-digit normalization, classification, and Mod-11 check-digit (DV)."""

from __future__ import annotations

from .validators import is_corporate_ruc, is_date_collision, strip_dv_suffix

NATURAL_CLASSIFICATIONS: frozenset[str] = frozenset(
    {
        "NATURAL_CEDULA",
        "NATURAL_AV",
        "NATURAL_PI",
        "NATURAL_PE",
        "NATURAL_E",
        "NATURAL_N",
        "NATURAL_NT",
    }
)


def _is_valid_prov(prov: str) -> bool:
    return prov.isdigit() and not prov.startswith("0") and 1 <= int(prov) <= 13


def _is_valid_libro_tomo(libro: str, tomo: str) -> bool:
    return (
        libro.isdigit()
        and tomo.isdigit()
        and 1 <= len(libro) <= 4
        and 1 <= len(tomo) <= 6
        and int(libro) >= 1
        and int(tomo) >= 1
    )


def classify_panama_id(token: str) -> str:
    """Classify a Panama ID/RUC string into natural, juridica, date collision, or invalid."""
    if not isinstance(token, str):
        return "INVALID"
    cleaned = token.strip().upper()
    if not cleaned:
        return "INVALID"

    core, dv = strip_dv_suffix(cleaned)
    if dv is None and is_date_collision(core):
        return "DATE_COLLISION"
    if is_corporate_ruc(cleaned):
        return "JURIDICA_CORP"

    parts = core.split("-")
    if len(parts) == 4:
        prov, middle, libro, tomo = parts
        if middle == "NT" and _is_valid_prov(prov) and _is_valid_libro_tomo(libro, tomo):
            return "NATURAL_NT"
        return "INVALID"

    if len(parts) != 3:
        return "INVALID"

    p0, libro, tomo = parts
    if not _is_valid_libro_tomo(libro, tomo):
        return "INVALID"

    if p0 == "PE":
        return "NATURAL_PE"
    if p0 == "E":
        return "NATURAL_E"
    if p0 == "N":
        return "NATURAL_N"
    if p0.endswith("AV") and _is_valid_prov(p0[:-2]):
        return "NATURAL_AV"
    if p0.endswith("PI") and _is_valid_prov(p0[:-2]):
        return "NATURAL_PI"
    if _is_valid_prov(p0):
        return "NATURAL_CEDULA"
    return "INVALID"


def normalize_to_ructb(ruc: str) -> tuple[str, int]:
    """Normalize a natural Panama ID/RUC to (20-digit RUCTB vector, sw flag)."""
    kind = classify_panama_id(ruc)
    if kind not in NATURAL_CLASSIFICATIONS:
        raise ValueError(f"Unsupported or invalid Panama natural RUC/cedula: {ruc!r} ({kind})")

    core, _ = strip_dv_suffix(ruc.strip().upper())
    parts = core.split("-")

    if kind == "NATURAL_NT":
        prov, _, libro, tomo = parts
        body = prov.zfill(2) + "43" + libro.zfill(4) + tomo.zfill(5)
        return body.rjust(20, "0"), 1

    p0, libro, tomo = parts
    if kind == "NATURAL_CEDULA":
        body = p0.zfill(2) + "00" + libro.zfill(4) + tomo.zfill(5)
    elif kind == "NATURAL_AV":
        body = p0[:-2].zfill(2) + "15" + libro.zfill(4) + tomo.zfill(5)
    elif kind == "NATURAL_PI":
        body = p0[:-2].zfill(2) + "79" + libro.zfill(4) + tomo.zfill(5)
    elif kind == "NATURAL_N":
        body = "0050" + libro.zfill(4) + tomo.zfill(5)
    elif kind == "NATURAL_E":
        body = "0055" + libro.zfill(4) + tomo.zfill(5)
    else:  # NATURAL_PE
        body = "0075" + libro.zfill(4) + tomo.zfill(5)
    return body.rjust(20, "0"), 0


def _mod11_pass(digits: list[int], sw: int) -> int:
    total = 0
    weight = 2
    for digit in reversed(digits):
        if sw == 1 and weight == 11:
            weight = 2
        total += digit * weight
        weight += 1
    rem = total % 11
    return 0 if rem in (0, 1) else 11 - rem


def calcular_dv_ructb(ruc: str) -> str:
    """Compute the two-digit DGI RUCTB Mod-11 check digit (DV) for a natural Panama ID."""
    vec_str, sw = normalize_to_ructb(ruc)
    digits = [int(ch) for ch in vec_str]
    dv1 = _mod11_pass(digits, sw)
    dv2 = _mod11_pass([*digits, dv1], sw)
    return f"{dv1}{dv2}"


def verify_ruc_dv(ruc: str, dv: str) -> bool:
    """Verify whether a two-digit DV matches the RUCTB check digit of ruc."""
    if not isinstance(ruc, str) or not isinstance(dv, str):
        return False
    cleaned_dv = dv.strip()
    if not (cleaned_dv.isdigit() and len(cleaned_dv) == 2):
        return False
    try:
        expected = calcular_dv_ructb(ruc)
    except ValueError:
        return False
    return expected == cleaned_dv
