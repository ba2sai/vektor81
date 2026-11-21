import { classifyPanamaId, stripOptionalDv } from "./ructb.js";

export const SENSITIVE_CONTEXT_ES: readonly string[] = [
  "vih",
  "sida",
  "seropositivo",
  "diagnostico",
  "diagnóstico",
  "historia clinica",
  "historia clínica",
  "expediente clinico",
  "expediente clínico",
  "css",
  "minsa",
  "paciente",
  "enfermedad",
  "patologia",
  "patología",
  "tratamiento medico",
  "tratamiento médico",
  "clinica",
  "clínica",
  "hospital",
  "receta medica",
  "receta médica",
  "oncologia",
  "oncología",
  "psiquiatrico",
  "psiquiátrico",
  "discapacidad",
  "embarazo",
  "biometrica",
  "biométrica",
  "biometrico",
  "biométrico",
  "biometria",
  "biometría",
  "huella",
  "huella dactilar",
  "reconocimiento facial",
  "adn",
  "genetico",
  "genético",
  "sindicato",
  "sindical",
  "afiliado",
  "afiliacion sindical",
  "afiliación sindical",
  "partido politico",
  "partido político",
  "religion",
  "religión",
  "orientacion sexual",
  "orientación sexual",
  "origen etnico",
  "origen étnico",
];

export const SENSITIVE_HEALTH_CONTEXT_ES: readonly string[] = [
  "vih",
  "sida",
  "seropositivo",
  "diagnostico",
  "diagnóstico",
  "historia clinica",
  "historia clínica",
  "expediente clinico",
  "expediente clínico",
  "css",
  "minsa",
  "paciente",
  "enfermedad",
  "patologia",
  "patología",
  "tratamiento medico",
  "tratamiento médico",
  "clinica",
  "clínica",
  "hospital",
  "receta medica",
  "receta médica",
  "oncologia",
  "oncología",
  "psiquiatrico",
  "psiquiátrico",
  "discapacidad",
  "embarazo",
];

export const CORPORATE_CONTEXT_ES: readonly string[] = [
  "sociedad anonima",
  "sociedad anónima",
  "s.a.",
  "s. a.",
  "s.r.l.",
  "s. de r.l.",
  "persona juridica",
  "persona jurídica",
  "razon social",
  "razón social",
  "registro publico",
  "registro público",
  "folio mercantil",
  "factura fiscal",
  "contribuyente juridico",
  "contribuyente jurídico",
  "proveedor",
  "b2b",
  "corp.",
  "ltda.",
  "inc.",
  "llc",
  "compania",
  "compañía",
  "empresa",
  "consorcio",
];

export const PASSPORT_CONTEXT_ES: readonly string[] = [
  "pasaporte",
  "apap",
  "autoridad de pasaportes",
  "viajero",
  "migracion",
  "migración",
  "visa",
  "consulado",
  "embajada",
  "documento de viaje",
];

export const FINANCIAL_CONTEXT_ES: readonly string[] = [
  "swift",
  "bic",
  "ach",
  "transferencia",
  "cuenta bancaria",
  "cuenta de ahorros",
  "cuenta corriente",
  "banco",
  "bancaria",
  "bancario",
  "tarjeta",
  "tarjeta de credito",
  "tarjeta de crédito",
  "tarjeta de debito",
  "tarjeta de débito",
  "tarjeta corporativa",
  "pago",
  "iban",
  "remesa",
  "sbp",
  "superintendencia de bancos",
];

export const IDENTITY_CONTEXT_ES: readonly string[] = [
  "cedula",
  "cédula",
  "cip",
  "c.i.p.",
  "portador",
  "portadora",
  "cedula de identidad",
  "cédula de identidad",
  "documento personal",
  "identidad personal",
];

/**
 * Normalizes Spanish text to lowercase without combining diacritics for accent-tolerant matching.
 */
export function normalizeForContext(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function escapeRegex(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Returns matching context keywords from a list using whole-token boundaries.
 */
export function findContextMatches(text: string, keywords: readonly string[]): string[] {
  const normalizedText = normalizeForContext(text);
  const matched = new Set<string>();

  for (const rawKeyword of keywords) {
    const kw = normalizeForContext(rawKeyword).trim();
    if (!kw) {
      continue;
    }
    const pattern = new RegExp(`(?<![a-z0-9])${escapeRegex(kw)}(?![a-z0-9])`, "i");
    if (pattern.test(normalizedText)) {
      matched.add(kw);
    }
  }

  return Array.from(matched);
}

function isValidCalendarPair(day: number, month: number, year: number): boolean {
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    return false;
  }
  const daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day > daysInMonth[month - 1]) {
    return false;
  }
  if (month === 2 && day === 29) {
    return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  }
  return true;
}

/**
 * Detects whether a numeric hyphenated token collides with a calendar date (DD-MM-YYYY, MM-DD-YYYY, YYYY-MM-DD).
 */
export function isDateCollision(token: string): boolean {
  const { core } = stripOptionalDv(token);
  const trimmed = core.trim();
  if (/[A-Za-z]/.test(trimmed)) {
    return false;
  }

  const match = /^(\d{1,4})-(\d{1,2})-(\d{1,4})$/.exec(trimmed);
  if (!match) {
    return false;
  }

  const aStr = match[1];
  const bStr = match[2];
  const cStr = match[3];
  const a = Number(aStr);
  const b = Number(bStr);
  const c = Number(cStr);

  // DD-MM-YYYY or MM-DD-YYYY
  if (cStr.length === 4 && c >= 1900 && c <= 2099 && aStr.length <= 2 && bStr.length <= 2) {
    return isValidCalendarPair(a, b, c) || isValidCalendarPair(b, a, c);
  }

  // YYYY-MM-DD
  if (aStr.length === 4 && a >= 1900 && a <= 2099 && bStr.length <= 2 && cStr.length <= 2) {
    return isValidCalendarPair(c, b, a);
  }

  return false;
}

/**
 * Returns true if the token represents a Panama corporate (persona juridica) RUC rather than a natural ID.
 */
export function isCorporateRuc(token: string): boolean {
  return classifyPanamaId(token) === "CORPORATE_RUC";
}

/**
 * Validates payment card numbers using the Luhn mod-10 algorithm.
 */
export function isValidLuhn(cardNumber: string): boolean {
  const digits = cardNumber.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(digits)) {
    return false;
  }
  if (/^(\d)\1+$/.test(digits)) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Validates an ISO 9362 SWIFT/BIC code registered in Panama (country code PA at positions 5-6).
 */
export function isValidPanamaSwift(code: string): boolean {
  const clean = code.trim().toUpperCase();
  return /^[A-Z]{4}PA[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/.test(clean);
}
