import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  analyzeText,
  calcularDvRuctb,
  classifyPanamaId,
  hashPiiSha256,
  hashPiiSha256Sync,
  isCorporateRuc,
  isDateCollision,
  isValidLuhn,
  isValidPanamaSwift,
  maskPiiValue,
  normalizeToRuctb,
  verifyRucDv,
  type PanamaIdKind,
} from "../src/index.js";

interface SharedVectors {
  version: string;
  valid_natural_ids: Array<{ token: string; expected_kind: PanamaIdKind; description: string }>;
  date_collisions_must_reject: string[];
  corporate_juridica_must_exclude: Array<{ token: string; reason: string }>;
  contextual_documents: Array<{
    id: string;
    text: string;
    expect_natural_identity_match?: boolean;
    expected_tokens?: string[];
    expect_sensitive?: boolean;
    expect_passport_match?: boolean;
    expected_passport?: string;
    expect_swift_match?: boolean;
    expected_swift?: string;
    expect_card_match?: boolean;
    expected_card?: string;
  }>;
  ructb_dv_vectors: Array<{
    ruc_input: string;
    expected_ructb: string;
    expected_sw: 0 | 1;
    expected_dv: string;
  }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(here, "../../shared-contracts/panama_pii_test_vectors.json");
const vectors: SharedVectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

describe("panama-pii-ts shared test vectors", () => {
  it("classifies and detects all valid_natural_ids", () => {
    for (const item of vectors.valid_natural_ids) {
      expect(classifyPanamaId(item.token)).toBe(item.expected_kind);
      expect(isDateCollision(item.token)).toBe(false);
      expect(isCorporateRuc(item.token)).toBe(false);
      expect(normalizeToRuctb(item.token)).not.toBeNull();

      const analysis = analyzeText(`Titular identificado: ${item.token}`);
      const naturalFindings = analysis.findings.filter(
        (f) => f.entity_type === "PA_IDENTIDAD_NATURAL"
      );
      expect(naturalFindings.length).toBe(1);
      expect(naturalFindings[0].value).toBe(item.token);
      expect(naturalFindings[0].kind).toBe(item.expected_kind);
    }
  });

  it("rejects all date_collisions_must_reject", () => {
    for (const token of vectors.date_collisions_must_reject) {
      expect(isDateCollision(token)).toBe(true);
      const analysis = analyzeText(`Fecha registrada ${token} en documento`);
      const naturalFindings = analysis.findings.filter(
        (f) => f.entity_type === "PA_IDENTIDAD_NATURAL"
      );
      expect(naturalFindings).toHaveLength(0);
    }
  });

  it("excludes all corporate_juridica_must_exclude RUCs from natural identities", () => {
    for (const item of vectors.corporate_juridica_must_exclude) {
      expect(classifyPanamaId(item.token)).toBe("CORPORATE_RUC");
      expect(isCorporateRuc(item.token)).toBe(true);
      expect(normalizeToRuctb(item.token)).toBeNull();

      const analysis = analyzeText(`RUC empresarial ${item.token}`);
      const naturalFindings = analysis.findings.filter(
        (f) => f.entity_type === "PA_IDENTIDAD_NATURAL"
      );
      expect(naturalFindings).toHaveLength(0);
    }
  });

  it("matches all 9 ructb_dv_vectors bit-for-bit", () => {
    for (const vec of vectors.ructb_dv_vectors) {
      const normalized = normalizeToRuctb(vec.ruc_input);
      expect(normalized).not.toBeNull();
      expect(normalized?.ructb).toBe(vec.expected_ructb);
      expect(normalized?.sw).toBe(vec.expected_sw);

      const dv = calcularDvRuctb(vec.expected_ructb, vec.expected_sw);
      expect(dv).toBe(vec.expected_dv);

      expect(verifyRucDv(vec.ruc_input, vec.expected_dv)).toBe(true);
      expect(verifyRucDv(`${vec.ruc_input} DV ${vec.expected_dv}`)).toBe(true);

      const wrongDv = vec.expected_dv === "99" ? "98" : "99";
      expect(verifyRucDv(vec.ruc_input, wrongDv)).toBe(false);
      expect(verifyRucDv(`${vec.ruc_input} DV ${wrongDv}`)).toBe(false);
    }
  });

  it("evaluates all contextual_documents accurately", () => {
    for (const doc of vectors.contextual_documents) {
      const result = analyzeText(doc.text);

      if (doc.expect_natural_identity_match !== undefined) {
        const natural = result.findings.filter((f) => f.entity_type === "PA_IDENTIDAD_NATURAL");
        if (doc.expect_natural_identity_match) {
          expect(natural.length).toBeGreaterThan(0);
          if (doc.expected_tokens) {
            expect(natural.map((f) => f.value)).toEqual(doc.expected_tokens);
          }
        } else {
          expect(natural).toHaveLength(0);
        }
      }

      if (doc.expect_sensitive !== undefined) {
        expect(result.has_sensitive_data).toBe(doc.expect_sensitive);
        if (doc.expect_sensitive) {
          expect(result.findings.some((f) => f.is_sensitive && f.severity === "CRITICAL")).toBe(
            true
          );
        }
      }

      if (doc.expect_passport_match !== undefined) {
        const passports = result.findings.filter((f) => f.entity_type === "PA_PASAPORTE");
        if (doc.expect_passport_match) {
          expect(passports.map((f) => f.value)).toContain(doc.expected_passport);
        } else {
          expect(passports).toHaveLength(0);
        }
      }

      if (doc.expect_swift_match !== undefined) {
        const swifts = result.findings.filter((f) => f.entity_type === "PA_SWIFT_PA");
        if (doc.expect_swift_match) {
          expect(swifts.map((f) => f.value)).toContain(doc.expected_swift);
        } else {
          expect(swifts).toHaveLength(0);
        }
      }

      if (doc.expect_card_match !== undefined) {
        const cards = result.findings.filter((f) => f.entity_type === "PA_TARJETA_PAGO");
        if (doc.expect_card_match) {
          expect(cards.map((f) => f.value)).toContain(doc.expected_card);
        } else {
          expect(cards).toHaveLength(0);
        }
      }
    }
  });
});

describe("validators, masking, hashing, and additional entity types", () => {
  it("validates Luhn and Panama SWIFT codes directly", () => {
    expect(isValidLuhn("4532015112830366")).toBe(true);
    expect(isValidLuhn("4532-0151-1283-0366")).toBe(true);
    expect(isValidLuhn("4532015112830367")).toBe(false);
    expect(isValidLuhn("0000000000000000")).toBe(false);

    expect(isValidPanamaSwift("BAGEPAPAXXX")).toBe(true);
    expect(isValidPanamaSwift("BAGEPAPA")).toBe(true);
    expect(isValidPanamaSwift("BAGEUS33XXX")).toBe(false);
  });

  it("masks PII values and produces identical WebCrypto and pure-JS SHA-256 hashes", async () => {
    expect(maskPiiValue("8-888-1234", "PA_IDENTIDAD_NATURAL")).toBe("8-8***34");
    expect(maskPiiValue("4532015112830366", "PA_TARJETA_PAGO")).toBe("4532********0366");
    expect(maskPiiValue("ana.gomez@empresa.pa", "EMAIL_PERSONAL")).toBe("an***@empresa.pa");
    expect(maskPiiValue("1234")).toBe("***");

    const samples = ["8-888-1234", "cédula 8-714-2219 diagnóstico VIH", ""];
    for (const sample of samples) {
      const expected = createHash("sha256").update(sample, "utf8").digest("hex");
      expect(hashPiiSha256Sync(sample)).toBe(expected);
      expect(await hashPiiSha256(sample)).toBe(expected);
    }
  });

  it("detects EMAIL_PERSONAL and rejects invalid explicit DV", () => {
    const emailRes = analyzeText("Contacto de soporte: maria.perez@correo.pa y cédula 8-888-1234 DV 49");
    expect(emailRes.counts.EMAIL_PERSONAL).toBe(1);
    expect(emailRes.counts.PA_IDENTIDAD_NATURAL).toBe(1);
    expect(emailRes.findings.find((f) => f.entity_type === "PA_IDENTIDAD_NATURAL")?.dv_valid).toBe(
      true
    );

    const badDvRes = analyzeText("Documento 8-888-1234 DV 99");
    expect(badDvRes.counts.PA_IDENTIDAD_NATURAL).toBe(0);
    expect(badDvRes.vetoed_tokens).toContainEqual({
      token: "8-888-1234 DV 99",
      reason: "invalid_dv",
    });
  });
});
