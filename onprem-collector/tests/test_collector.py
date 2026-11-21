"""Comprehensive unittest suite for Vektor81 v2 On-Premise Collector."""

from __future__ import annotations

import asyncio
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from docx import Document
from fastapi.testclient import TestClient
from openpyxl import Workbook
from PIL import Image
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

COLLECTOR_ROOT = Path(__file__).resolve().parents[1]
if str(COLLECTOR_ROOT) not in sys.path:
    sys.path.insert(0, str(COLLECTOR_ROOT))

from app import models  # noqa: E402
from app.connectors.adguard_connector import AdGuardConnector  # noqa: E402
from app.extractors import extract_text_from_bytes, extract_text_from_file  # noqa: E402
from app.health_monitor import collect_health_snapshot  # noqa: E402
from app.main import app  # noqa: E402
from app.pii_bridge import (  # noqa: E402
    analyze_text,
    evaluate_retention_violation,
    hash_pii_sha256,
)
from app.scanners.db_scanner import DbScanner  # noqa: E402
from app.scanners.smb_scanner import WindowsSmbScanner  # noqa: E402
from app.sync_client import ControlPlaneSyncClient  # noqa: E402


def _build_docx_bytes(paragraph_text: str, table_rows: list[list[str]]) -> bytes:
    doc = Document()
    doc.add_paragraph(paragraph_text)
    if table_rows:
        table = doc.add_table(rows=len(table_rows), cols=len(table_rows[0]))
        for r_idx, row in enumerate(table_rows):
            for c_idx, val in enumerate(row):
                table.cell(r_idx, c_idx).text = val
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _build_xlsx_bytes(sheets: dict[str, list[list[str]]]) -> bytes:
    wb = Workbook()
    first = True
    for sheet_name, rows in sheets.items():
        ws = wb.active if first else wb.create_sheet(title=sheet_name)
        ws.title = sheet_name
        first = False
        for row in rows:
            ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _build_compressed_pdf_bytes(text: str) -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})}
    )
    safe_text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = DecodedStreamObject()
    stream.set_data(f"BT /F1 11 Tf 72 720 Td ({safe_text}) Tj ET".encode("latin-1"))
    page[NameObject("/Contents")] = writer._add_object(stream)
    page.compress_content_streams()
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


class TestExtractorsAndPanamaPii(unittest.TestCase):
    """Verify real DOCX, XLSX, compressed PDF, OCR fallback, and Panama PII disambiguation."""

    SAMPLE_CORPUS = (
        "Titular cedula: 8-888-1234. "
        "Titular historico cedula: 8AV-123-4567. "
        "Fecha de vencimiento: 12-05-2026. "
        "RUC Juridico: 155-123456-2."
    )

    def _assert_only_natural_cedulas(self, text: str) -> None:
        findings = analyze_text(text, regulatory_profile="ANTAI_LEY81")
        hashes = {f.value_sha256 for f in findings}
        entity_types = {f.entity_type for f in findings}

        self.assertEqual(entity_types, {"PA_IDENTIDAD_NATURAL"})
        self.assertEqual(len(findings), 2)
        self.assertIn(hash_pii_sha256("8-888-1234"), hashes)
        self.assertIn(hash_pii_sha256("8AV-123-4567"), hashes)
        self.assertNotIn(hash_pii_sha256("12-05-2026"), hashes)
        self.assertNotIn(hash_pii_sha256("155-123456-2"), hashes)
        for f in findings:
            self.assertNotIn("8-888-1234", f.masked_value)
            self.assertNotIn("8AV-123-4567", f.masked_value)

    def test_docx_xlsx_and_compressed_pdf_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            docx_path = tmp / "contrato_clientes.docx"
            docx_path.write_bytes(
                _build_docx_bytes(
                    "Documento oficial de auditoria. Fecha de vencimiento: 12-05-2026.",
                    [
                        ["Campo", "Valor"],
                        ["Cedula Titular", "8-888-1234"],
                        ["Cedula Pre-2006", "8AV-123-4567"],
                        ["RUC Sociedad", "155-123456-2"],
                    ],
                )
            )
            docx_res = extract_text_from_file(docx_path)
            self.assertIsNone(docx_res.error)
            self.assertEqual(docx_res.file_type, "docx")
            self._assert_only_natural_cedulas(docx_res.text)

            xlsx_path = tmp / "planilla.xlsx"
            xlsx_path.write_bytes(
                _build_xlsx_bytes(
                    {
                        "Nominas": [
                            ["Cedula", "Fecha", "RUC Empresa"],
                            ["8-888-1234", "12-05-2026", "155-123456-2"],
                        ],
                        "Historico": [
                            ["Cedula Anterior"],
                            ["8AV-123-4567"],
                        ],
                    }
                )
            )
            xlsx_res = extract_text_from_file(xlsx_path)
            self.assertIsNone(xlsx_res.error)
            self.assertEqual(xlsx_res.file_type, "xlsx")
            self._assert_only_natural_cedulas(xlsx_res.text)

            pdf_bytes = _build_compressed_pdf_bytes(self.SAMPLE_CORPUS)
            self.assertIn(b"/FlateDecode", pdf_bytes)
            pdf_path = tmp / "expediente_comprimido.pdf"
            pdf_path.write_bytes(pdf_bytes)
            pdf_res = extract_text_from_file(pdf_path)
            self.assertIsNone(pdf_res.error)
            self.assertEqual(pdf_res.file_type, "pdf")
            self._assert_only_natural_cedulas(pdf_res.text)

    def test_image_ocr_graceful_degradation_when_tesseract_missing(self) -> None:
        img = Image.new("RGB", (60, 20), color=(255, 255, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        with patch("app.extractors.is_tesseract_available", return_value=False):
            res = extract_text_from_bytes(png_bytes, "scan_cedula.png")

        self.assertEqual(res.file_type, "png")
        self.assertEqual(res.text, "")
        self.assertFalse(res.ocr_used)
        self.assertFalse(res.ocr_available)
        self.assertIsNotNone(res.error)


class TestDbScannerAndRetention(unittest.TestCase):
    """Verify SQLite DbScanner masking, date-collision rejection, and retention rules."""

    def test_sqlite_scan_masks_pii_and_flags_retention_violation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "legacy_core.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                """
                CREATE TABLE clientes (
                    id INTEGER PRIMARY KEY,
                    nombre TEXT,
                    cedula TEXT,
                    ruc_empresa TEXT,
                    fecha_evento TEXT,
                    created_at TEXT
                )
                """
            )
            conn.execute(
                "INSERT INTO clientes (nombre, cedula, ruc_empresa, fecha_evento, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("Carlos Perez", "8-888-1234", "155-123456-2", "12-05-2026", "2016-01-10T09:00:00Z"),
            )
            conn.execute(
                "INSERT INTO clientes (nombre, cedula, ruc_empresa, fecha_evento, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("Ana Gomez", "8AV-123-4567", "155-123456-2", "12-05-2026", "2017-03-20T12:00:00Z"),
            )
            conn.commit()
            conn.close()

            scanner = DbScanner(
                db_type="sqlite",
                sqlite_path=str(db_path),
                regulatory_profile="ANTAI_LEY81",
                tenant_id="banco-istmo",
                sample_limit=200,
            )
            result = scanner.run_scan()

            self.assertFalse(result["is_simulated"])
            self.assertEqual(result["tables_scanned"], 1)
            self.assertEqual(result["rows_sampled"], 2)
            self.assertEqual(result["findings_count"], 1)
            self.assertEqual(result["retention_violations_count"], 1)

            finding = result["findings"][0]
            self.assertEqual(finding["source_type"], "SQL_DB")
            self.assertEqual(finding["location_path"], "clientes.cedula")
            self.assertEqual(finding["entity_type"], "PA_IDENTIDAD_NATURAL")
            self.assertEqual(finding["match_count"], 2)
            self.assertTrue(finding["retention_violation"])
            self.assertGreater(finding["retention_age_days"], 2555)

            serialized = json.dumps(result)
            self.assertNotIn("8-888-1234", serialized)
            self.assertNotIn("8AV-123-4567", serialized)

    def test_salud_ley68_clinical_under_20y_not_violation(self) -> None:
        self.assertFalse(evaluate_retention_violation("SALUD_LEY68", 3650, is_clinical=True))
        self.assertTrue(evaluate_retention_violation("SALUD_LEY68", 3000, is_clinical=False))
        self.assertTrue(evaluate_retention_violation("SALUD_LEY68", 7400, is_clinical=True))

    def test_missing_non_sqlite_driver_raises_diagnostic_error(self) -> None:
        with patch.dict(sys.modules, {"oracledb": None}):
            scanner = DbScanner(db_type="oracle", host="127.0.0.1", database="ORCL")
            with self.assertRaises(RuntimeError) as ctx:
                scanner.run_scan()
            self.assertIn("oracledb", str(ctx.exception))


class TestSmbScannerHardening(unittest.TestCase):
    """Verify SMB scanner does not simulate by default and parses real files via retrieveFile."""

    def test_smb_unreachable_fails_by_default_without_simulation(self) -> None:
        scanner = WindowsSmbScanner(server_ip="127.0.0.1", port=65445)
        with patch("app.scanners.smb_scanner.SMBConnection") as mock_smb_cls:
            mock_conn = mock_smb_cls.return_value
            mock_conn.connect.side_effect = OSError("Connection refused")
            with self.assertRaises(RuntimeError):
                scanner.run_scan()

    def test_smb_live_connection_reads_full_docx_and_checks_retention(self) -> None:
        docx_bytes = _build_docx_bytes(
            "Expediente colaborador cedula: 8-888-1234",
            [["RUC Empresa", "155-123456-2"], ["Fecha", "12-05-2026"]],
        )
        old_ts = 1420070400.0  # 2015-01-01 UTC (> 7 years)

        class FakeShare:
            def __init__(self, name: str):
                self.name = name
                self.isSpecial = False

        class FakeFile:
            def __init__(self, filename: str, is_dir: bool, size: int, mtime: float):
                self.filename = filename
                self.isDirectory = is_dir
                self.file_size = size
                self.last_write_time = mtime

        class FakeConn:
            def listShares(self, timeout=5):
                return [FakeShare("Planilla")]

            def listPath(self, share_name, path, timeout=4):
                return [
                    FakeFile(".", True, 0, old_ts),
                    FakeFile("..", True, 0, old_ts),
                    FakeFile("nomina_2015.docx", False, len(docx_bytes), old_ts),
                ]

            def retrieveFile(self, share_name, path, file_obj, timeout=10):
                file_obj.write(docx_bytes)

        scanner = WindowsSmbScanner(server_ip="192.168.10.5", max_file_mb=10)
        res = scanner._scan_live_connection(FakeConn(), "FS01", False, 0.0)

        self.assertFalse(res["is_simulated"])
        self.assertEqual(res["files_with_pii_count"], 1)
        self.assertEqual(res["cedula_matches_count"], 1)
        self.assertEqual(res["retention_violations_count"], 1)
        self.assertNotIn("8-888-1234", json.dumps(res))


class TestAdGuardAndHealthMonitor(unittest.TestCase):
    """Verify AdGuardConnector offline reporting and health_monitor heartbeats."""

    def test_adguard_offline_reports_honest_status_without_crashing(self) -> None:
        def failing_handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        connector = AdGuardConnector(base_url="http://adguard.local:3000")

        async def _run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(failing_handler)) as client:
                return await connector.fetch_querylog_stats(tenant_id="banco-istmo", client=client)

        res = asyncio.run(_run())
        self.assertEqual(res["adguard_status"], "OFFLINE")
        self.assertFalse(res["adguard_live_connected"])
        self.assertIsNotNone(res["last_error"])
        self.assertEqual(res["shadow_ai_hits_total"], 0)

    def test_adguard_online_matches_ai_domains_json(self) -> None:
        def ok_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/control/status":
                return httpx.Response(200, json={"protection_enabled": True, "version": "0.107.52"})
            if request.url.path == "/control/querylog":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {"question": {"name": "chatgpt.com."}, "client": "10.0.0.15", "rules": []},
                            {"question": {"name": "www.ilovepdf.com"}, "client": "10.0.0.15", "rules": ["blocked"]},
                            {"question": {"name": "intranet.local"}, "client": "10.0.0.15", "rules": []},
                        ]
                    },
                )
            return httpx.Response(404)

        connector = AdGuardConnector(base_url="http://adguard.local:3000")

        async def _run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(ok_handler)) as client:
                return await connector.fetch_querylog_stats(tenant_id="banco-istmo", client=client)

        res = asyncio.run(_run())
        self.assertEqual(res["adguard_status"], "ONLINE")
        self.assertTrue(res["adguard_live_connected"])
        self.assertEqual(res["total_queries_inspected"], 3)
        self.assertEqual(res["shadow_ai_hits_total"], 2)
        self.assertEqual(len(res["shadow_ai_batch"]["events"]), 2)


class TestFastApiEndpointsAndSyncClient(unittest.TestCase):
    """End-to-end API auth, legal report citations, and sync_client offline queue recovery."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_env = dict(os.environ)
        db_file = Path(self._tmpdir.name) / "collector_test.db"
        models.reconfigure_database(f"sqlite:///{db_file.as_posix()}")

        os.environ["VEKTOR81_ENV"] = "production"
        os.environ["ONPREM_API_TOKEN"] = "test-collector-secret-token"
        os.environ["ALLOWED_ORIGINS"] = "http://localhost:5173"
        os.environ["ENABLE_DEMO_TOOLS"] = "false"
        os.environ["TENANT_ID"] = "banco-istmo"
        os.environ["REGULATORY_PROFILE"] = "SBP_001_2022"
        os.environ["ADGUARD_URL"] = "http://127.0.0.1:65432"
        os.environ["CLOUDFLARED_METRICS_URL"] = "disabled"
        os.environ["CONTROL_PLANE_URL"] = ""
        os.environ["COLLECTOR_TOKEN"] = ""

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._orig_env)
        models.engine.dispose()
        self._tmpdir.cleanup()

    def test_auth_health_legal_report_and_ficha_tecnica(self) -> None:
        with TestClient(app) as client:
            # Public liveness ping works without auth
            ping_resp = client.get("/api/v1/health/ping")
            self.assertEqual(ping_resp.status_code, 200)
            self.assertTrue(ping_resp.json()["ok"])

            # Protected routes reject missing/invalid token with 401
            self.assertEqual(client.get("/api/v1/health").status_code, 401)
            self.assertEqual(
                client.get("/api/v1/dashboard", headers={"Authorization": "Bearer wrong"}).status_code,
                401,
            )

            headers = {"Authorization": "Bearer test-collector-secret-token"}

            # No auto-seeding on startup
            dash_empty = client.get("/api/v1/dashboard", headers=headers)
            self.assertEqual(dash_empty.status_code, 200)
            self.assertEqual(dash_empty.json()["kpis"]["audited_endpoints"], 0)

            # Demo seeding gated by ENABLE_DEMO_TOOLS=true
            self.assertEqual(
                client.post("/api/v1/admin/seed-demo", headers=headers).status_code,
                403,
            )

            # Health endpoint succeeds with valid token
            health_resp = client.get("/api/v1/health", headers=headers)
            self.assertEqual(health_resp.status_code, 200)
            health_json = health_resp.json()
            self.assertTrue(health_json["ok"])
            self.assertGreaterEqual(len(health_json["heartbeats"]), 5)

            # Create real temp SQLite DB and scan via /api/v1/scan-db
            ext_db = Path(self._tmpdir.name) / "bank_customers.db"
            conn = sqlite3.connect(ext_db)
            conn.execute(
                "CREATE TABLE kyc (id INTEGER PRIMARY KEY, titular TEXT, cedula TEXT, created_at TEXT)"
            )
            conn.execute(
                "INSERT INTO kyc (titular, cedula, created_at) VALUES (?, ?, ?)",
                ("Maria Lopez", "8-888-1234", "2015-06-01T00:00:00Z"),
            )
            conn.commit()
            conn.close()

            scan_resp = client.post(
                "/api/v1/scan-db",
                headers=headers,
                json={"db_type": "sqlite", "sqlite_path": str(ext_db)},
            )
            self.assertEqual(scan_resp.status_code, 200)
            self.assertEqual(scan_resp.json()["retention_violations_count"], 1)

            # Report HTML verifies exact updated Panama legal citations & zero stale errors
            report_resp = client.get("/api/v1/report/pdf?format=html", headers=headers)
            self.assertEqual(report_resp.status_code, 200)
            html = report_resp.text
            self.assertIn("DE 285", html)
            self.assertIn("B/. 1,000", html)
            self.assertIn("Arts. 15-16", html)
            self.assertIn("Art. 45", html)
            self.assertIn("Acuerdo 001-2022 SBP", html)
            self.assertIn("Ley 68 de 2003", html)
            self.assertIn("clausura", html)
            self.assertIn("imprescriptibilidad", html)
            self.assertIn("Cloudflare", html)
            self.assertNotIn("USD $", html)
            self.assertNotIn("Artículo 27 de la Ley 81", html)

            # Ficha técnica JSON returns deterministic SHA-256 hash
            ficha_resp = client.get("/api/v1/ficha-tecnica", headers=headers)
            self.assertEqual(ficha_resp.status_code, 200)
            ficha = ficha_resp.json()
            self.assertEqual(ficha["document_type"], "FICHA_TECNICA_LEY_81_PANAMA")
            self.assertEqual(len(ficha["sha256_hash"]), 64)

            # Endpoint ingest + heartbeat endpoint compatibility with PowerShell agent v2
            ingest_resp = client.post(
                "/api/v1/ingest",
                headers=headers,
                json={
                    "tenant_id": "banco-istmo",
                    "hostname": "PC-TEST-01",
                    "username": "CORP\\mrodriguez",
                    "ip_address": "10.10.20.14",
                    "shadow_ai_dns_hits": [
                        {"domain": "chatgpt.com", "count": 5, "category": "LLM Conversacional"}
                    ],
                    "risky_extensions": [
                        {
                            "extension_id": "ext1",
                            "name": "AI Sidebar",
                            "browser": "Chrome",
                            "permissions": ["<all_urls>"],
                            "has_all_urls": True,
                        }
                    ],
                    "box_audit": {
                        "provider": "BoxDrive",
                        "installed": True,
                        "total_synced_files": 12,
                        "sensitive_files_count": 2,
                        "dlp_enabled": False,
                        "sample_files_masked": ["Planilla_****.xlsx"],
                    },
                },
            )
            self.assertEqual(ingest_resp.status_code, 200)
            self.assertEqual(ingest_resp.json()["hostname"], "PC-TEST-01")

            hb_resp = client.post(
                "/api/v1/health/heartbeat",
                headers=headers,
                json={
                    "tenant_id": "banco-istmo",
                    "component_layer": "ENDPOINT_AGENT",
                    "component_id": "PC-TEST-01",
                    "status": "ONLINE",
                    "version": "2.0.0",
                },
            )
            self.assertEqual(hb_resp.status_code, 200)
            self.assertTrue(hb_resp.json()["ok"])

    def test_sync_client_queues_on_failure_and_flushes_on_recovery(self) -> None:
        state = {"online": False, "requests": []}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            if not state["online"]:
                return httpx.Response(503, text="Control Plane temporarily unreachable")
            state["requests"].append(
                {
                    "path": request.url.path,
                    "auth": request.headers.get("authorization"),
                    "tenant": request.headers.get("x-tenant-id"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(200, json={"ok": True})

        sync_client = ControlPlaneSyncClient(
            control_plane_url="https://cp.example.workers.dev",
            collector_token="cp-collector-token",
            tenant_id="banco-istmo",
            transport=httpx.MockTransport(mock_handler),
        )

        batch = {
            "tenant_id": "banco-istmo",
            "scan_id": "db-abc123",
            "scanner_layer": "DB_CONNECTOR",
            "is_simulated": False,
            "total_assets_scanned": 1,
            "scan_duration_ms": 12,
            "findings": [
                {
                    "source_type": "SQL_DB",
                    "repository_name": "bank.db",
                    "location_path": "kyc.cedula",
                    "entity_type": "PA_IDENTIDAD_NATURAL",
                    "masked_sample": "8-8***34",
                    "value_sha256": hash_pii_sha256("8-888-1234"),
                    "match_count": 1,
                    "is_sensitive": False,
                    "severity": "HIGH",
                    "retention_age_days": 3000,
                    "retention_violation": True,
                }
            ],
        }

        db = models.SessionLocal()
        try:
            async def _run():
                # 1. Push fails -> persisted in PendingSyncQueue
                first = await sync_client.send_or_queue(db, "/api/v2/ingest/findings", batch)
                self.assertFalse(first["sent"])
                self.assertTrue(first["queued"])
                self.assertEqual(
                    db.query(models.PendingSyncQueue)
                    .filter(models.PendingSyncQueue.status == "PENDING")
                    .count(),
                    1,
                )

                # 2. Control Plane recovers -> sync_once flushes backlog + pushes heartbeats
                state["online"] = True
                hb_snapshot = await collect_health_snapshot(
                    db=db,
                    tenant_id="banco-istmo",
                    adguard_connector=AdGuardConnector(base_url="http://127.0.0.1:65432"),
                    tunnel_metrics_url="disabled",
                )
                recovery = await sync_client.sync_once(
                    db=db,
                    include_heartbeats=True,
                    health_snapshot=hb_snapshot,
                )
                return recovery

            recovery_res = asyncio.run(_run())
            self.assertTrue(recovery_res["ok"])
            self.assertEqual(recovery_res["flushed_from_queue"], 1)
            self.assertEqual(recovery_res["pending_queue_remaining"], 0)
            self.assertGreaterEqual(recovery_res["heartbeats_pushed"], 5)

            sent_paths = [r["path"] for r in state["requests"]]
            self.assertEqual(sent_paths[0], "/api/v2/ingest/findings")
            self.assertIn("/api/v2/health/heartbeat", sent_paths)
            self.assertEqual(state["requests"][0]["auth"], "Bearer cp-collector-token")
            self.assertEqual(state["requests"][0]["tenant"], "banco-istmo")
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
