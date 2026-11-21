export type PanamaIdKind =
  | "NATURAL_CEDULA"
  | "NATURAL_AV"
  | "NATURAL_PI"
  | "NATURAL_PE"
  | "NATURAL_E"
  | "NATURAL_N"
  | "NATURAL_NT"
  | "CORPORATE_RUC"
  | "UNKNOWN";

export type NaturalPanamaIdKind = Exclude<PanamaIdKind, "CORPORATE_RUC" | "UNKNOWN">;

export interface RuctbNormalization {
  ructb: string;
  sw: 0 | 1;
  kind: NaturalPanamaIdKind;
  cleanId: string;
  dvProvided?: string;
}

interface ParsedNaturalPrefix {
  kind: NaturalPanamaIdKind;
  prefixCode: string;
  sw: 0 | 1;
  libro: string;
  tomo: string;
  cleanId: string;
}

const VALID_PROVINCE_RE = /^(?:[1-9]|1[0-3])$/;
const VALID_LIBRO_RE = /^\d{1,4}$/;
const VALID_TOMO_RE = /^\d{1,6}$/;
const DV_SUFFIX_RE = /^(.*?)\s*DV\s*([0-9A-Za-z]+)$/i;

function isPositiveSegment(value: string, pattern: RegExp): boolean {
  return pattern.test(value) && Number(value) >= 1;
}

export function stripOptionalDv(raw: string): { core: string; dvProvided?: string } {
  const trimmed = raw.trim();
  const match = DV_SUFFIX_RE.exec(trimmed);
  if (!match) {
    return { core: trimmed };
  }
  return {
    core: match[1].trim(),
    dvProvided: match[2].trim(),
  };
}

function parseNaturalParts(cleanUpper: string): ParsedNaturalPrefix | null {
  const parts = cleanUpper.split("-");

  if (parts.length === 4) {
    const [prov, mid, libro, tomo] = parts;
    if (
      mid === "NT" &&
      VALID_PROVINCE_RE.test(prov) &&
      isPositiveSegment(libro, VALID_LIBRO_RE) &&
      isPositiveSegment(tomo, VALID_TOMO_RE)
    ) {
      return {
        kind: "NATURAL_NT",
        prefixCode: `${prov.padStart(2, "0")}43`,
        sw: 1,
        libro,
        tomo,
        cleanId: cleanUpper,
      };
    }
    return null;
  }

  if (parts.length !== 3) {
    return null;
  }

  const [head, libro, tomo] = parts;
  if (!isPositiveSegment(libro, VALID_LIBRO_RE) || !isPositiveSegment(tomo, VALID_TOMO_RE)) {
    return null;
  }

  if (head === "N") {
    return { kind: "NATURAL_N", prefixCode: "0050", sw: 0, libro, tomo, cleanId: cleanUpper };
  }
  if (head === "E") {
    return { kind: "NATURAL_E", prefixCode: "0055", sw: 0, libro, tomo, cleanId: cleanUpper };
  }
  if (head === "PE") {
    return { kind: "NATURAL_PE", prefixCode: "0075", sw: 0, libro, tomo, cleanId: cleanUpper };
  }

  if (head.endsWith("AV")) {
    const prov = head.slice(0, -2);
    if (VALID_PROVINCE_RE.test(prov)) {
      return {
        kind: "NATURAL_AV",
        prefixCode: `${prov.padStart(2, "0")}15`,
        sw: 0,
        libro,
        tomo,
        cleanId: cleanUpper,
      };
    }
    return null;
  }

  if (head.endsWith("PI")) {
    const prov = head.slice(0, -2);
    if (VALID_PROVINCE_RE.test(prov)) {
      return {
        kind: "NATURAL_PI",
        prefixCode: `${prov.padStart(2, "0")}79`,
        sw: 0,
        libro,
        tomo,
        cleanId: cleanUpper,
      };
    }
    return null;
  }

  if (VALID_PROVINCE_RE.test(head)) {
    return {
      kind: "NATURAL_CEDULA",
      prefixCode: `${head.padStart(2, "0")}00`,
      sw: 0,
      libro,
      tomo,
      cleanId: cleanUpper,
    };
  }

  return null;
}

/**
 * Classifies a Panama personal identity or corporate RUC token structurally.
 */
export function classifyPanamaId(raw: string): PanamaIdKind {
  const { core } = stripOptionalDv(raw);
  const upper = core.toUpperCase();
  const parsed = parseNaturalParts(upper);
  if (parsed) {
    return parsed.kind;
  }

  const parts = upper.split("-");
  if (
    parts.length === 3 &&
    /^\d+$/.test(parts[0]) &&
    /^\d+$/.test(parts[1]) &&
    /^\d+$/.test(parts[2])
  ) {
    const firstNum = Number(parts[0]);
    if (firstNum > 13 || (VALID_PROVINCE_RE.test(parts[0]) && parts[1].length >= 5)) {
      return "CORPORATE_RUC";
    }
  }

  return "UNKNOWN";
}

/**
 * Normalizes a valid Panama natural identity / RUC string into the 20-digit DGI RUCTB format.
 * Returns null for corporate RUCs or structurally invalid identifiers.
 */
export function normalizeToRuctb(raw: string): RuctbNormalization | null {
  const { core, dvProvided } = stripOptionalDv(raw);
  const upper = core.toUpperCase();
  const parsed = parseNaturalParts(upper);
  if (!parsed) {
    return null;
  }

  const ructb = (
    parsed.prefixCode +
    parsed.libro.padStart(4, "0") +
    parsed.tomo.padStart(5, "0")
  ).padStart(20, "0");

  return {
    ructb,
    sw: parsed.sw,
    kind: parsed.kind,
    cleanId: parsed.cleanId,
    ...(dvProvided !== undefined ? { dvProvided } : {}),
  };
}

function mod11Pass(digits: string, sw: 0 | 1): number {
  let total = 0;
  let j = 2;
  for (let i = digits.length - 1; i >= 0; i--) {
    if (sw === 1 && j === 11) {
      j = 2;
    }
    total += Number(digits[i]) * j;
    j++;
  }
  const rem = total % 11;
  return rem === 0 || rem === 1 ? 0 : 11 - rem;
}

/**
 * Calculates the 2-digit Panama DGI check digit (DV) for a 20-digit RUCTB string.
 */
export function calcularDvRuctb(ructb: string, sw: 0 | 1 = 0): string {
  const clean = ructb.trim();
  if (!/^\d{1,20}$/.test(clean)) {
    throw new Error(`Invalid RUCTB input: "${ructb}"`);
  }
  const padded = clean.padStart(20, "0");
  const dv1 = mod11Pass(padded, sw);
  const dv2 = mod11Pass(`${padded}${dv1}`, sw);
  return `${dv1}${dv2}`;
}

/**
 * Verifies a Panama natural RUC against either an embedded "DV XX" suffix or an explicit 2-digit DV argument.
 */
export function verifyRucDv(rucInput: string, explicitDv?: string): boolean {
  const normalized = normalizeToRuctb(rucInput);
  if (!normalized) {
    return false;
  }
  const candidateDv = explicitDv !== undefined ? explicitDv.trim() : normalized.dvProvided;
  if (!candidateDv || !/^\d{2}$/.test(candidateDv)) {
    return false;
  }
  return calcularDvRuctb(normalized.ructb, normalized.sw) === candidateDv;
}
