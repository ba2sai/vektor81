"""Comprehensive unittest suite validating 100% of shared Panama PII test vectors."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

VECTORS_PATH = (
    PACKAGE_ROOT.parent / "shared-contracts" / "panama_pii_test_vectors.json"
)

import panama_pii  # noqa: E402
from panama_pii import (  # noqa: E402
    PRESIDIO_AVAILABLE,
    FallbackPanamaAnalyzer,
    PanamaCedulaRucRecognizer,
    PanamaPassportRecognizer,
    PanamaSensitiveHealthRecognizer,
    PiiFinding,
    analyze_text,
    build_panama_analyzer,
    calcular_dv_ructb,
    classify_panama_id,
    hash_pii_sha256,
    is_corporate_ruc,
    is_date_collision,
    is_valid_luhn,
    is_valid_panama_swift,
    mask_pii_value,
    normalize_to_ructb,
    presidio_adapter,
    verify_ruc_dv,
)


class TestPanamaPiiSharedVectors(unittest.TestCase):
    """Verify 100% parity with packages/shared-contracts/panama_pii_test_vectors.json."""

    vectors: dict

    @classmethod
    def setUpClass(cls) -> None:
        with VECTORS_PATH.open("r", encoding="utf-8") as fh:
            cls.vectors = json.load(fh)

    def test_valid_natural_ids(self) -> None:
        for entry in self.vectors["valid_natural_ids"]:
            token = entry["token"]
            expected_kind = entry["expected_kind"]
            with self.subTest(token=token, expected_kind=expected_kind):
                self.assertEqual(classify_panama_id(token), expected_kind)
                self.assertFalse(is_date_collision(token))
                self.assertFalse(is_corporate_ruc(token))

                findings = analyze_text(f"Titular identificado con {token}")
                nat_findings = [f for f in findings if f.entity_type == "PA_IDENTIDAD_NATURAL"]
                self.assertEqual(len(nat_findings), 1)
                self.assertEqual(nat_findings[0].value_sha256, hash_pii_sha256(token))
                self.assertNotIn(token, nat_findings[0].masked_value)

    def test_date_collisions_must_reject(self) -> None:
        for date_token in self.vectors["date_collisions_must_reject"]:
            with self.subTest(date_token=date_token):
                self.assertTrue(is_date_collision(date_token))
                self.assertFalse(is_corporate_ruc(date_token))
                self.assertEqual(classify_panama_id(date_token), "DATE_COLLISION")
                self.assertEqual(analyze_text(f"Fecha de emisión {date_token}"), [])
                with self.assertRaises(ValueError):
                    normalize_to_ructb(date_token)

    def test_corporate_juridica_must_exclude(self) -> None:
        for entry in self.vectors["corporate_juridica_must_exclude"]:
            token = entry["token"]
            with self.subTest(token=token):
                self.assertTrue(is_corporate_ruc(token))
                self.assertFalse(is_date_collision(token))
                self.assertEqual(classify_panama_id(token), "JURIDICA_CORP")
                self.assertEqual(analyze_text(f"RUC empresa {token}"), [])
                with self.assertRaises(ValueError):
                    normalize_to_ructb(token)

    def test_contextual_documents_corpus(self) -> None:
        for doc in self.vectors["contextual_documents"]:
            doc_id = doc["id"]
            text = doc["text"]
            findings = analyze_text(text)

            with self.subTest(doc_id=doc_id):
                nat = [f for f in findings if f.entity_type == "PA_IDENTIDAD_NATURAL"]
                passports = [f for f in findings if f.entity_type == "PA_PASAPORTE"]
                swifts = [f for f in findings if f.entity_type == "PA_SWIFT_PA"]
                cards = [f for f in findings if f.entity_type == "PA_TARJETA_PAGO"]

                if "expect_natural_identity_match" in doc:
                    if doc["expect_natural_identity_match"]:
                        self.assertGreaterEqual(len(nat), 1)
                        matched_tokens = [text[f.start : f.end] for f in nat]
                        for expected_token in doc.get("expected_tokens", []):
                            self.assertIn(expected_token, matched_tokens)
                        if "expect_dlp_min_score" in doc:
                            for finding in nat:
                                self.assertGreaterEqual(finding.score, doc["expect_dlp_min_score"])
                    else:
                        self.assertEqual(nat, [])

                if doc.get("expect_sensitive"):
                    self.assertTrue(any(f.is_sensitive for f in findings))
                    for finding in nat:
                        self.assertTrue(finding.is_sensitive)
                        self.assertGreaterEqual(finding.score, doc["expect_dlp_min_score"])

                if "expect_passport_match" in doc:
                    if doc["expect_passport_match"]:
                        self.assertEqual(len(passports), 1)
                        self.assertEqual(text[passports[0].start : passports[0].end], doc["expected_passport"])
                    else:
                        self.assertEqual(passports, [])

                if "expect_swift_match" in doc:
                    if doc["expect_swift_match"]:
                        self.assertEqual(len(swifts), 1)
                        self.assertEqual(text[swifts[0].start : swifts[0].end], doc["expected_swift"])
                    else:
                        self.assertEqual(swifts, [])

                if "expect_card_match" in doc:
                    if doc["expect_card_match"]:
                        self.assertEqual(len(cards), 1)
                        self.assertEqual(text[cards[0].start : cards[0].end], doc["expected_card"])
                    else:
                        self.assertEqual(cards, [])

    def test_ructb_dv_vectors(self) -> None:
        for vec in self.vectors["ructb_dv_vectors"]:
            ruc_input = vec["ruc_input"]
            expected_ructb = vec["expected_ructb"]
            expected_sw = vec["expected_sw"]
            expected_dv = vec["expected_dv"]
            with self.subTest(ruc_input=ruc_input):
                ructb, sw = normalize_to_ructb(ruc_input)
                self.assertEqual(len(ructb), 20)
                self.assertEqual(ructb, expected_ructb)
                self.assertEqual(sw, expected_sw)
                self.assertEqual(calcular_dv_ructb(ruc_input), expected_dv)
                self.assertTrue(verify_ruc_dv(ruc_input, expected_dv))
                wrong_dv = f"{(int(expected_dv) + 1) % 100:02d}"
                self.assertFalse(verify_ruc_dv(ruc_input, wrong_dv))


class TestPanamaPiiAdditionalBehavior(unittest.TestCase):
    """Edge cases for validators, regulatory profiles, masking, emails, and Presidio fallback."""

    def test_validators_and_edge_cases(self) -> None:
        self.assertTrue(is_valid_luhn("4532015112830366"))
        self.assertTrue(is_valid_luhn("4532-0151-1283-0366"))
        self.assertFalse(is_valid_luhn("4532015112830367"))
        self.assertFalse(is_valid_luhn("0000000000000000"))
        self.assertFalse(is_valid_luhn("123456"))

        self.assertTrue(is_valid_panama_swift("BAGEPAPAXXX"))
        self.assertTrue(is_valid_panama_swift("BCTOPAPA"))
        self.assertFalse(is_valid_panama_swift("BAGEUS33XXX"))
        self.assertFalse(is_valid_panama_swift("INVALID"))

        # Random uppercase word matching SWIFT syntax without financial context is ignored.
        self.assertEqual(analyze_text("Please enter SOMEPASS to continue"), [])

        # Edge RUC / classification checks.
        self.assertEqual(classify_panama_id("pe-12-4401"), "NATURAL_PE")
        self.assertEqual(classify_panama_id("8-888-1234 DV 49"), "NATURAL_CEDULA")
        self.assertEqual(classify_panama_id("2026-11-21"), "DATE_COLLISION")
        self.assertEqual(classify_panama_id("01-200-3000"), "INVALID")
        self.assertEqual(classify_panama_id(""), "INVALID")
        self.assertFalse(verify_ruc_dv("12-05-2026", "00"))
        self.assertFalse(verify_ruc_dv("8-888-1234", "4"))

    def test_regulatory_profiles_and_health_detection(self) -> None:
        clinical_text = "Paciente atendido por diagnóstico VIH en historia clínica CSS"
        antai_findings = analyze_text(clinical_text, regulatory_profile="ANTAI_LEY81")
        ley68_findings = analyze_text(clinical_text, regulatory_profile="SALUD_LEY68")

        antai_health = [f for f in antai_findings if f.entity_type == "PA_DATO_SENSIBLE_SALUD"]
        ley68_health = [f for f in ley68_findings if f.entity_type == "PA_DATO_SENSIBLE_SALUD"]
        self.assertEqual(len(antai_health), 1)
        self.assertEqual(len(ley68_health), 1)
        self.assertTrue(ley68_health[0].is_sensitive)
        self.assertGreater(ley68_health[0].score, antai_health[0].score)

        # Generic non-patient article should not emit PA_DATO_SENSIBLE_SALUD.
        article = "Artículo informativo sobre prevención del VIH en la región"
        self.assertEqual(
            [f for f in analyze_text(article) if f.entity_type == "PA_DATO_SENSIBLE_SALUD"],
            [],
        )

        # SBP_001_2022 boosts Panama SWIFT scores.
        bank_text = "Transferencia ACH vía SWIFT BAGEPAPAXXX hacia cuenta corriente"
        sbp = analyze_text(bank_text, regulatory_profile="SBP_001_2022")
        antai = analyze_text(bank_text, regulatory_profile="ANTAI_LEY81")
        self.assertGreater(sbp[0].score, antai[0].score)

    def test_emails_and_masking_hashing(self) -> None:
        text = "Contacto del titular: maria.gonzalez@gmail.com"
        findings = analyze_text(text)
        emails = [f for f in findings if f.entity_type == "EMAIL_PERSONAL"]
        self.assertEqual(len(emails), 1)
        self.assertIsInstance(emails[0], PiiFinding)
        self.assertNotIn("maria.gonzalez", emails[0].masked_value)
        self.assertEqual(emails[0].value_sha256, hash_pii_sha256("maria.gonzalez@gmail.com"))

        self.assertEqual(mask_pii_value("VIH"), "***")
        self.assertEqual(mask_pii_value("8-888-1234"), "8-8***34")
        self.assertEqual(mask_pii_value("4532015112830366"), "4532********0366")
        self.assertEqual(len(hash_pii_sha256("8-888-1234")), 64)

    def test_presidio_adapter_graceful_degradation(self) -> None:
        self.assertIsInstance(PRESIDIO_AVAILABLE, bool)
        self.assertEqual(panama_pii.__version__, "2.0.0")

        ced_rec = PanamaCedulaRucRecognizer()
        pass_rec = PanamaPassportRecognizer()
        health_rec = PanamaSensitiveHealthRecognizer(regulatory_profile="SALUD_LEY68")

        ced_res = ced_rec.analyze("Portador de cédula 8-888-1234")
        self.assertEqual(len(ced_res), 1)
        self.assertEqual(ced_res[0].entity_type, "PA_IDENTIDAD_NATURAL")

        pass_res = pass_rec.analyze("Pasaporte APAP PA1234567")
        self.assertEqual(len(pass_res), 1)
        self.assertEqual(pass_res[0].entity_type, "PA_PASAPORTE")
        self.assertEqual(pass_rec.analyze("Inventario AB1234567"), [])

        health_res = health_rec.analyze("Paciente con cédula 8-888-1234 diagnóstico VIH")
        self.assertEqual(len(health_res), 1)
        self.assertEqual(health_res[0].entity_type, "PA_DATO_SENSIBLE_SALUD")

        analyzer = build_panama_analyzer(language="es", regulatory_profile="ANTAI_LEY81")
        results = analyzer.analyze(
            "Paciente con cédula 8-888-1234, diagnóstico VIH en historia clínica CSS",
            language="es",
        )
        entities = {r.entity_type for r in results}
        self.assertIn("PA_IDENTIDAD_NATURAL", entities)
        self.assertIn("PA_DATO_SENSIBLE_SALUD", entities)

        # Verify simulated Presidio engine failure also degrades cleanly to FallbackPanamaAnalyzer.
        with (
            patch.object(presidio_adapter, "PRESIDIO_AVAILABLE", True),
            patch.object(presidio_adapter, "AnalyzerEngine", object()),
            patch.object(presidio_adapter, "RecognizerRegistry", side_effect=OSError("no spacy model")),
        ):
            degraded = build_panama_analyzer()
            self.assertIsInstance(degraded, FallbackPanamaAnalyzer)
            self.assertEqual(len(degraded.analyze("Cédula 8-888-1234", language="es")), 1)


if __name__ == "__main__":
    unittest.main()
