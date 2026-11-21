import { hashPiiSha256Sync, maskPiiValue } from "./masking.js";
import {
  calcularDvRuctb,
  classifyPanamaId,
  normalizeToRuctb,
  verifyRucDv,
  type PanamaIdKind,
} from "./ructb.js";
import {
  CORPORATE_CONTEXT_ES,
  FINANCIAL_CONTEXT_ES,
  IDENTITY_CONTEXT_ES,
  PASSPORT_CONTEXT_ES,
  SENSITIVE_CONTEXT_ES,
  SENSITIVE_HEALTH_CONTEXT_ES,
  findContextMatches,
  isCorporateRuc,
  isDateCollision,
  isValidLuhn,
  isValidPanamaSwift,
} from "./validators.js";

export type PanamaEntityType =
  | "PA_IDENTIDAD_NATURAL"
  | "PA_PASAPORTE"
  | "PA_DATO_SENSIBLE_SALUD"
  | "PA_TARJETA_PAGO"
  | "PA_SWIFT_PA"
  | "EMAIL_PERSONAL";

export type AlertSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface PiiMatch {
  entity_type: PanamaEntityType;
  value: string;
  masked_sample: string;
  value_sha256: string;
  start: number;
  end: number;
  is_sensitive: boolean;
  severity: AlertSeverity;
  kind?: PanamaIdKind;
  ructb?: string;
  calculated_dv?: string;
  dv_provided?: string;
  dv_valid?: boolean;
  context_signals?: string[];
}

export interface VetoedToken {
  token: string;
  reason: string;
}

export interface TextAnalysisResult {
  regulatory_profile: string;
  findings: PiiMatch[];
  counts: Record<PanamaEntityType, number>;
  has_sensitive_data: boolean;
  corporate_context_detected: boolean;
  identity_context_detected: boolean;
  vetoed_tokens: VetoedToken[];
}

const PANAMA_ID_CANDIDATE_RE =
  /(?<![A-Za-z0-9-])(?:(?:[1-9]|1[0-3])-NT-\d{1,4}-\d{1,6}|(?:[1-9]|1[0-3])(?:AV|PI)-\d{1,4}-\d{1,6}|(?:PE|E|N)-\d{1,4}-\d{1,6}|\d{1,8}-\d{1,6}-\d{1,7})(?:\s+DV\s*[0-9A-Za-z]+)?(?![A-Za-z0-9-])/gi;

const PASSPORT_CANDIDATE_RE = /\bP[ADEOS]\d{7}\b/g;
const SWIFT_CANDIDATE_RE = /\b[A-Z]{4}PA[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;
const CARD_CANDIDATE_RE =
  /(?<!\d)(?:\d{4}[ -]){3}\d{1,7}(?!\d)|(?<!\d)\d{4}[ -]\d{6}[ -]\d{5}(?!\d)|(?<!\d)\d{13,19}(?!\d)/g;
const EMAIL_CANDIDATE_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

function createEmptyCounts(): Record<PanamaEntityType, number> {
  return {
    PA_IDENTIDAD_NATURAL: 0,
    PA_PASAPORTE: 0,
    PA_DATO_SENSIBLE_SALUD: 0,
    PA_TARJETA_PAGO: 0,
    PA_SWIFT_PA: 0,
    EMAIL_PERSONAL: 0,
  };
}

function buildMatch(
  entityType: PanamaEntityType,
  value: string,
  start: number,
  end: number,
  isSensitive: boolean,
  severity: AlertSeverity,
  extra?: Partial<Omit<PiiMatch, "entity_type" | "value" | "masked_sample" | "value_sha256" | "start" | "end" | "is_sensitive" | "severity">>
): PiiMatch {
  return {
    entity_type: entityType,
    value,
    masked_sample: maskPiiValue(value, entityType),
    value_sha256: hashPiiSha256Sync(value),
    start,
    end,
    is_sensitive: isSensitive,
    severity,
    ...extra,
  };
}

/**
 * Analyzes text for Panama personal data under Ley 81, DE 285, SBP 001-2022, and Salud Ley 68.
 */
export function analyzeText(
  text: string,
  regulatoryProfile: string = "ANTAI_LEY81"
): TextAnalysisResult {
  const counts = createEmptyCounts();
  const findings: PiiMatch[] = [];
  const vetoedTokens: VetoedToken[] = [];

  if (!text || !text.trim()) {
    return {
      regulatory_profile: regulatoryProfile,
      findings,
      counts,
      has_sensitive_data: false,
      corporate_context_detected: false,
      identity_context_detected: false,
      vetoed_tokens: vetoedTokens,
    };
  }

  const sensitiveSignals = findContextMatches(text, SENSITIVE_CONTEXT_ES);
  const healthSignals = findContextMatches(text, SENSITIVE_HEALTH_CONTEXT_ES);
  const corporateSignals = findContextMatches(text, CORPORATE_CONTEXT_ES);
  const identitySignals = findContextMatches(text, IDENTITY_CONTEXT_ES);
  const passportSignals = findContextMatches(text, PASSPORT_CONTEXT_ES);
  const financialSignals = findContextMatches(text, FINANCIAL_CONTEXT_ES);

  const hasSensitiveContext = sensitiveSignals.length > 0;
  const hasHealthContext = healthSignals.length > 0;
  const corporateContextDetected = corporateSignals.length > 0;
  const identityContextDetected = identitySignals.length > 0;

  // 1. Panama Natural Identity / RUC candidates
  for (const match of text.matchAll(PANAMA_ID_CANDIDATE_RE)) {
    const rawToken = match[0];
    const start = match.index ?? 0;
    const end = start + rawToken.length;

    if (isDateCollision(rawToken)) {
      vetoedTokens.push({ token: rawToken, reason: "date_collision" });
      continue;
    }

    if (isCorporateRuc(rawToken)) {
      vetoedTokens.push({ token: rawToken, reason: "corporate_ruc" });
      continue;
    }

    const kind = classifyPanamaId(rawToken);
    if (kind === "UNKNOWN") {
      vetoedTokens.push({ token: rawToken, reason: "invalid_te_structure" });
      continue;
    }

    const normalized = normalizeToRuctb(rawToken);
    if (!normalized) {
      vetoedTokens.push({ token: rawToken, reason: "invalid_ructb_structure" });
      continue;
    }

    if (normalized.dvProvided !== undefined && !verifyRucDv(rawToken)) {
      vetoedTokens.push({ token: rawToken, reason: "invalid_dv" });
      continue;
    }

    if (corporateContextDetected && !identityContextDetected) {
      vetoedTokens.push({ token: rawToken, reason: "corporate_context_without_explicit_identity" });
      continue;
    }

    const calculatedDv = calcularDvRuctb(normalized.ructb, normalized.sw);
    const dvValid = normalized.dvProvided !== undefined ? calculatedDv === normalized.dvProvided : undefined;
    const severity: AlertSeverity = hasSensitiveContext
      ? "CRITICAL"
      : regulatoryProfile === "SALUD_LEY68" && hasHealthContext
        ? "CRITICAL"
        : "HIGH";

    findings.push(
      buildMatch("PA_IDENTIDAD_NATURAL", rawToken, start, end, hasSensitiveContext, severity, {
        kind,
        ructb: normalized.ructb,
        calculated_dv: calculatedDv,
        ...(normalized.dvProvided !== undefined ? { dv_provided: normalized.dvProvided, dv_valid: dvValid } : {}),
        ...(hasSensitiveContext ? { context_signals: sensitiveSignals } : {}),
      })
    );
    counts.PA_IDENTIDAD_NATURAL++;
  }

  // 2. Panama Passports (APAP) — require passport context to avoid inventory-code false positives
  if (passportSignals.length > 0) {
    for (const match of text.matchAll(PASSPORT_CANDIDATE_RE)) {
      const rawToken = match[0];
      const start = match.index ?? 0;
      const end = start + rawToken.length;
      findings.push(
        buildMatch(
          "PA_PASAPORTE",
          rawToken,
          start,
          end,
          hasSensitiveContext,
          hasSensitiveContext ? "CRITICAL" : "HIGH",
          { context_signals: passportSignals }
        )
      );
      counts.PA_PASAPORTE++;
    }
  }

  // 3. Payment Cards (Luhn validated)
  for (const match of text.matchAll(CARD_CANDIDATE_RE)) {
    const rawToken = match[0];
    const digits = rawToken.replace(/[\s-]/g, "");
    if (!isValidLuhn(digits)) {
      vetoedTokens.push({ token: rawToken, reason: "luhn_failed" });
      continue;
    }
    if (financialSignals.length === 0 && !/^[2-6]/.test(digits)) {
      vetoedTokens.push({ token: rawToken, reason: "missing_financial_context" });
      continue;
    }
    const start = match.index ?? 0;
    const end = start + rawToken.length;
    const severity: AlertSeverity =
      regulatoryProfile === "SBP_001_2022" || hasSensitiveContext ? "CRITICAL" : "HIGH";
    findings.push(
      buildMatch("PA_TARJETA_PAGO", rawToken, start, end, hasSensitiveContext, severity, {
        ...(financialSignals.length > 0 ? { context_signals: financialSignals } : {}),
      })
    );
    counts.PA_TARJETA_PAGO++;
  }

  // 4. Panama SWIFT / BIC codes (require financial context + PA country code)
  if (financialSignals.length > 0) {
    for (const match of text.matchAll(SWIFT_CANDIDATE_RE)) {
      const rawToken = match[0];
      if (!isValidPanamaSwift(rawToken)) {
        continue;
      }
      const start = match.index ?? 0;
      const end = start + rawToken.length;
      findings.push(
        buildMatch(
          "PA_SWIFT_PA",
          rawToken,
          start,
          end,
          false,
          regulatoryProfile === "SBP_001_2022" ? "HIGH" : "MEDIUM",
          { context_signals: financialSignals }
        )
      );
      counts.PA_SWIFT_PA++;
    }
  }

  // 5. Clinical / Health Sensitive Data indicator (Ley 81 + Ley 68)
  if (hasHealthContext) {
    const summarySignal = healthSignals.join(", ");
    findings.push(
      buildMatch("PA_DATO_SENSIBLE_SALUD", summarySignal, 0, text.length, true, "CRITICAL", {
        context_signals: healthSignals,
      })
    );
    counts.PA_DATO_SENSIBLE_SALUD++;
  }

  // 6. Emails
  for (const match of text.matchAll(EMAIL_CANDIDATE_RE)) {
    const rawToken = match[0];
    const start = match.index ?? 0;
    const end = start + rawToken.length;
    findings.push(
      buildMatch(
        "EMAIL_PERSONAL",
        rawToken,
        start,
        end,
        hasSensitiveContext,
        hasSensitiveContext ? "HIGH" : "LOW"
      )
    );
    counts.EMAIL_PERSONAL++;
  }

  return {
    regulatory_profile: regulatoryProfile,
    findings,
    counts,
    has_sensitive_data: hasSensitiveContext,
    corporate_context_detected: corporateContextDetected,
    identity_context_detected: identityContextDetected,
    vetoed_tokens: vetoedTokens,
  };
}
