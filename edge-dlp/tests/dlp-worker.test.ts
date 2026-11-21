import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  DlpValidationEntrypoint,
  validatePanamaDlpExcerpt,
  type DlpValidationInput,
} from "../src/index.js";

interface SharedVectors {
  valid_natural_ids: Array<{ token: string; expected_kind: string }>;
  date_collisions_must_reject: string[];
  corporate_juridica_must_exclude: Array<{ token: string; reason: string }>;
  contextual_documents: Array<{
    id: string;
    text: string;
    expect_dlp_decision?: "veto";
    expect_dlp_min_score?: number;
  }>;
  ructb_dv_vectors: Array<{
    ruc_input: string;
    expected_dv: string;
  }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(here, "../../packages/shared-contracts/panama_pii_test_vectors.json");
const vectors: SharedVectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

function encodeUtf8Base64(text: string): string {
  return Buffer.from(text, "utf8").toString("base64");
}

function makeInput(textOrBase64: string, alreadyBase64 = false): DlpValidationInput {
  return {
    entryId: "panama-cedula-entry",
    accountId: "acct-vektor81-test",
    userId: "usr-001",
    start: 0,
    end: 10,
    excerpt: alreadyBase64 ? textOrBase64 : encodeUtf8Base64(textOrBase64),
    requestInfo: {
      method: "POST",
      url: "https://api.example.pa/upload",
    },
  };
}

describe("edge-dlp DlpValidationEntrypoint & validatePanamaDlpExcerpt", () => {
  const mockCtx = {
    waitUntil: () => {},
    passThroughOnException: () => {},
    props: {},
  } as unknown as ExecutionContext;
  const entrypoint = new DlpValidationEntrypoint(mockCtx, {} as Cloudflare.Env);

  it("decodes UTF-8 accented Spanish base64 excerpts reliably", async () => {
    const accentedCorpVeto =
      "Razón social Inversiones Pacífico S.A., Registro Público 8-123-4567 sin mención personal";
    expect(await entrypoint.validate(makeInput(accentedCorpVeto))).toEqual({ score: "veto" });

    const accentedHealth =
      "Paciente con cédula 8-888-1234 y diagnóstico VIH en historia clínica";
    expect(await entrypoint.validate(makeInput(accentedHealth))).toEqual({ score: 0.95 });
  });

  it("vetoes empty and malformed base64 excerpts", async () => {
    expect(validatePanamaDlpExcerpt("")).toEqual({ score: "veto" });
    expect(validatePanamaDlpExcerpt("   ")).toEqual({ score: "veto" });
    expect(validatePanamaDlpExcerpt("!!!not-valid-base64!!!")).toEqual({ score: "veto" });
    expect(validatePanamaDlpExcerpt("abc")).toEqual({ score: "veto" });
    expect(validatePanamaDlpExcerpt(encodeUtf8Base64("   "))).toEqual({ score: "veto" });
    expect(await entrypoint.validate(makeInput("not$base64", true))).toEqual({ score: "veto" });
  });

  it("vetoes all date collisions and invalid TE structures", () => {
    for (const dateToken of vectors.date_collisions_must_reject) {
      expect(validatePanamaDlpExcerpt(encodeUtf8Base64(`Documento fechado ${dateToken}`))).toEqual({
        score: "veto",
      });
    }

    const invalidTeTokens = ["0-888-1234", "14-888-1234", "8-000-0000", "8-12345-1234", "01-234-5678"];
    for (const badToken of invalidTeTokens) {
      expect(validatePanamaDlpExcerpt(encodeUtf8Base64(`Identificador ${badToken}`))).toEqual({
        score: "veto",
      });
    }
  });

  it("vetoes corporate RUCs and corporate context without explicit cedula/cip/portador", () => {
    for (const corp of vectors.corporate_juridica_must_exclude) {
      expect(
        validatePanamaDlpExcerpt(encodeUtf8Base64(`Portador de la cédula RUC ${corp.token}`))
      ).toEqual({ score: "veto" });
    }

    const corpVetoDoc = vectors.contextual_documents.find((d) => d.id === "corp_without_cedula_veto");
    expect(corpVetoDoc).toBeDefined();
    expect(validatePanamaDlpExcerpt(encodeUtf8Base64(corpVetoDoc!.text))).toEqual({ score: "veto" });
  });

  it("accepts natural ID inside corporate context when explicit cedula/cip/portador keyword is present", async () => {
    const corpKeepDoc = vectors.contextual_documents.find(
      (d) => d.id === "corp_with_explicit_cedula_keep"
    );
    expect(corpKeepDoc).toBeDefined();

    const res = await entrypoint.validate(makeInput(corpKeepDoc!.text));
    expect(res).toEqual({ score: 0.65 });
    expect(typeof res.score === "number" && res.score >= corpKeepDoc!.expect_dlp_min_score!).toBe(
      true
    );

    const cipAccept = "Empresa Comercial S.A. colaborador con CIP 8-714-2219 en planilla";
    expect(validatePanamaDlpExcerpt(encodeUtf8Base64(cipAccept))).toEqual({ score: 0.65 });
  });

  it("elevates score to 0.95 when sensitive health or biometric context coexists", async () => {
    const healthDoc = vectors.contextual_documents.find(
      (d) => d.id === "sensitive_health_hiv_elevate"
    );
    const bioDoc = vectors.contextual_documents.find(
      (d) => d.id === "sensitive_biometric_union_elevate"
    );
    expect(healthDoc).toBeDefined();
    expect(bioDoc).toBeDefined();

    expect(await entrypoint.validate(makeInput(healthDoc!.text))).toEqual({ score: 0.95 });
    expect(await entrypoint.validate(makeInput(bioDoc!.text))).toEqual({ score: 0.95 });
  });

  it("scores 0.9 for valid natural RUC + matching DV and vetoes invalid explicit DV", async () => {
    for (const vec of vectors.ructb_dv_vectors) {
      const validText = `Contribuyente natural ${vec.ruc_input} DV ${vec.expected_dv}`;
      expect(await entrypoint.validate(makeInput(validText))).toEqual({ score: 0.9 });

      const wrongDv = vec.expected_dv === "99" ? "98" : "99";
      const invalidText = `Contribuyente natural ${vec.ruc_input} DV ${wrongDv}`;
      expect(await entrypoint.validate(makeInput(invalidText))).toEqual({ score: "veto" });
    }
  });

  it("scores 0.65 for all valid natural IDs without explicit DV or sensitive context", async () => {
    for (const item of vectors.valid_natural_ids) {
      const res = await entrypoint.validate(makeInput(`Titular registrado ${item.token}`));
      expect(res).toEqual({ score: 0.65 });
    }
  });
});
