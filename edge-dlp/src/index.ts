import {
  DlpValidation,
  type DlpValidationInput,
  type DlpValidationResult,
} from "@cloudflare/zt-types";
import {
  analyzeText,
  findContextMatches,
  SENSITIVE_CONTEXT_ES,
} from "@vektor81/panama-pii-ts";

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function decodeBase64Utf8(excerptBase64: string): string | null {
  if (typeof excerptBase64 !== "string") {
    return null;
  }
  const compact = excerptBase64.replace(/\s+/g, "");
  if (!compact || compact.length % 4 !== 0 || !BASE64_PATTERN.test(compact)) {
    return null;
  }

  try {
    const binary = atob(compact);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Pure helper validating a Base64-encoded UTF-8 DLP excerpt against Panama Ley 81 / DE 285 rules.
 */
export function validatePanamaDlpExcerpt(excerptBase64: string): DlpValidationResult {
  const decoded = decodeBase64Utf8(excerptBase64);
  if (!decoded || !decoded.trim()) {
    return { score: "veto" };
  }

  const analysis = analyzeText(decoded);
  const naturalFindings = analysis.findings.filter(
    (finding) => finding.entity_type === "PA_IDENTIDAD_NATURAL"
  );

  if (naturalFindings.length > 0) {
    const hasSensitiveContext =
      analysis.has_sensitive_data ||
      findContextMatches(decoded, SENSITIVE_CONTEXT_ES).length > 0;
    if (hasSensitiveContext) {
      return { score: 0.95 };
    }

    const hasValidExplicitDv = naturalFindings.some((finding) => finding.dv_valid === true);
    if (hasValidExplicitDv) {
      return { score: 0.9 };
    }

    return { score: 0.65 };
  }

  if (analysis.vetoed_tokens.length > 0) {
    return { score: "veto" };
  }

  const hasOtherSensitive =
    analysis.counts.PA_DATO_SENSIBLE_SALUD > 0 ||
    (analysis.has_sensitive_data && analysis.findings.length > 0);
  if (hasOtherSensitive) {
    return { score: 0.95 };
  }

  if (analysis.counts.PA_PASAPORTE > 0 || analysis.counts.PA_TARJETA_PAGO > 0) {
    return { score: 0.85 };
  }

  if (analysis.counts.PA_SWIFT_PA > 0) {
    return { score: 0.65 };
  }

  return { score: "veto" };
}

/**
 * Cloudflare Zero Trust DLP Custom Validation Worker entrypoint for Vektor81.
 */
export class DlpValidationEntrypoint extends DlpValidation {
  async validate(input: DlpValidationInput): Promise<DlpValidationResult> {
    if (!input || typeof input.excerpt !== "string") {
      return { score: "veto" };
    }
    return validatePanamaDlpExcerpt(input.excerpt);
  }
}

export type { DlpValidationInput, DlpValidationResult };
