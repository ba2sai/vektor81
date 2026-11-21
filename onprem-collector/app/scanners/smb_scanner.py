"""
Windows Server (SMB/CIFS) scanner using real document/OCR extractors and panama-pii-py.
"""

from __future__ import annotations

import io
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure

from ..extractors import IMAGE_EXTENSIONS, SUPPORTED_EXTENSIONS, extract_text_from_bytes
from ..pii_bridge import (
    PiiFinding,
    analyze_text,
    compute_finding_severity,
    evaluate_retention_violation,
    hash_pii_sha256,
    mask_pii_value,
)

CRITICAL_FOLDER_KEYWORDS = (
    "contratos",
    "contrato",
    "planilla",
    "nomina",
    "nómina",
    "finanzas",
    "contabilidad",
    "legal",
    "clientes",
    "rrhh",
    "recursos humanos",
    "facturacion",
    "bancos",
    "expedientes",
    "historias",
)

SYSTEM_SHARES = {"IPC$", "ADMIN$", "C$", "D$", "E$", "PRINT$", "FAX$", "NETLOGON", "SYSVOL"}


def is_critical_name(name: str) -> bool:
    normalized = name.lower().strip()
    return any(keyword in normalized for keyword in CRITICAL_FOLDER_KEYWORDS)


class WindowsSmbScanner:
    """SMB/CIFS scanner inspecting full documents up to max_file_mb using real extractors."""

    def __init__(
        self,
        server_ip: str,
        username: str = "",
        password: str = "",
        domain: str = "WORKGROUP",
        port: int = 445,
        max_depth: int = 3,
        max_file_mb: int = 10,
        regulatory_profile: str = "ANTAI_LEY81",
        tenant_id: str = "default-tenant",
    ):
        self.server_ip = server_ip
        self.username = username.strip()
        self.password = password
        self.domain = domain or "WORKGROUP"
        self.port = port
        self.max_depth = max_depth
        self.max_file_mb = max_file_mb
        self.max_file_bytes = max_file_mb * 1024 * 1024
        self.regulatory_profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
        self.tenant_id = tenant_id or "default-tenant"
        self.client_name = "VEKTOR81-COLL"

    def _resolve_netbios_name(self) -> str:
        try:
            host, _, _ = socket.gethostbyaddr(self.server_ip)
            return host.split(".")[0].upper()
        except Exception:
            return self.server_ip

    def run_scan(self, simulate_if_unreachable: bool = False) -> Dict[str, Any]:
        """Execute SMB audit. Simulation is disabled by default unless explicitly requested."""
        start_time = time.perf_counter()
        remote_name = self._resolve_netbios_name()
        is_guest_attempt = self.username == "" or self.username.lower() in ("guest", "anonymous")

        conn: Optional[SMBConnection] = None
        try:
            conn = SMBConnection(
                username=self.username,
                password=self.password,
                my_name=self.client_name,
                remote_name=remote_name,
                domain=self.domain,
                use_ntlm_v2=True,
                is_direct_tcp=(self.port == 445),
            )
            connected = conn.connect(self.server_ip, port=self.port, timeout=4)
            if not connected:
                raise ConnectionError(f"Autenticación SMB rechazada por {self.server_ip}:{self.port}")

            return self._scan_live_connection(conn, remote_name, is_guest_attempt, start_time)
        except Exception as exc:
            if simulate_if_unreachable:
                return self._generate_fallback_simulation(remote_name, str(exc), start_time)
            raise RuntimeError(
                f"No se pudo conectar al servidor SMB {self.server_ip}:{self.port} -> {exc}"
            ) from exc
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _scan_live_connection(
        self,
        conn: SMBConnection,
        remote_name: str,
        is_guest_attempt: bool,
        start_time: float,
    ) -> Dict[str, Any]:
        scan_id = f"smb-{uuid.uuid4().hex[:12]}"
        shares = conn.listShares(timeout=5)
        critical_shares_found: List[str] = []
        findings_detail: List[Dict[str, Any]] = []
        findings_v2: List[Dict[str, Any]] = []
        warnings: List[str] = []

        counters = {
            "office_files": 0,
            "pii_files": 0,
            "cedulas": 0,
            "passports": 0,
            "emails": 0,
            "sensitive": 0,
            "retention_violations": 0,
        }
        accessible_shares = 0

        for share in shares:
            share_name = share.name
            if share_name.upper() in SYSTEM_SHARES or getattr(share, "isSpecial", False):
                continue

            accessible_shares += 1
            if is_critical_name(share_name):
                critical_shares_found.append(share_name)

            self._walk_share(
                conn=conn,
                share_name=share_name,
                current_path="/",
                depth=1,
                critical_shares_found=critical_shares_found,
                findings_detail=findings_detail,
                findings_v2=findings_v2,
                counters=counters,
                warnings=warnings,
            )

        elapsed_ms = int((time.perf_counter() - start_time) * 1000)

        return {
            "scan_id": scan_id,
            "tenant_id": self.tenant_id,
            "regulatory_profile": self.regulatory_profile,
            "target_ip": self.server_ip,
            "server_name": remote_name,
            "auth_mode": (
                "Guest/Anonymous"
                if is_guest_attempt
                else f"Authenticated ({self.domain}\\{self.username})"
            ),
            "guest_access_allowed": is_guest_attempt,
            "is_simulated": False,
            "total_shares": accessible_shares,
            "critical_shares_found": sorted(list(set(critical_shares_found))),
            "total_office_pdf_files": counters["office_files"],
            "files_with_pii_count": counters["pii_files"],
            "cedula_matches_count": counters["cedulas"],
            "ruc_matches_count": 0,
            "email_matches_count": counters["emails"],
            "sensitive_findings_count": counters["sensitive"],
            "retention_violations_count": counters["retention_violations"],
            "findings_detail": findings_detail[:100],
            "findings_v2": findings_v2[:200],
            "finding_batch_payload": {
                "tenant_id": self.tenant_id,
                "scan_id": scan_id,
                "scanner_layer": "SMB_CONNECTOR",
                "is_simulated": False,
                "total_assets_scanned": counters["office_files"],
                "scan_duration_ms": elapsed_ms,
                "findings": findings_v2[:200],
            },
            "warnings": warnings[:50],
            "scan_duration_ms": elapsed_ms,
        }

    def _walk_share(
        self,
        conn: SMBConnection,
        share_name: str,
        current_path: str,
        depth: int,
        critical_shares_found: List[str],
        findings_detail: List[Dict[str, Any]],
        findings_v2: List[Dict[str, Any]],
        counters: Dict[str, int],
        warnings: List[str],
    ) -> None:
        if depth > self.max_depth:
            return

        try:
            items = conn.listPath(share_name, current_path, timeout=4)
        except OperationFailure:
            return
        except Exception:
            return

        now_ts = time.time()
        detected_iso = datetime.now(timezone.utc).isoformat()

        for item in items:
            filename = item.filename
            if filename in (".", ".."):
                continue

            full_rel_path = f"{current_path.rstrip('/')}/{filename}"

            if item.isDirectory:
                if is_critical_name(filename):
                    critical_label = (
                        f"\\\\{self.server_ip}\\{share_name}{full_rel_path.replace('/', '\\')}"
                    )
                    if critical_label not in critical_shares_found:
                        critical_shares_found.append(critical_label)
                self._walk_share(
                    conn=conn,
                    share_name=share_name,
                    current_path=full_rel_path,
                    depth=depth + 1,
                    critical_shares_found=critical_shares_found,
                    findings_detail=findings_detail,
                    findings_v2=findings_v2,
                    counters=counters,
                    warnings=warnings,
                )
                continue

            ext = Path(filename).suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue

            counters["office_files"] += 1

            if item.file_size > self.max_file_bytes:
                warnings.append(
                    f"Skipped oversized file ({round(item.file_size / (1024 * 1024), 1)} MB > {self.max_file_mb} MB): {share_name}{full_rel_path}"
                )
                continue

            raw_bytes = b""
            if item.file_size > 0:
                buf = io.BytesIO()
                try:
                    conn.retrieveFile(share_name, full_rel_path, buf, timeout=10)
                    raw_bytes = buf.getvalue()
                except Exception as exc:
                    warnings.append(f"Failed retrieving {share_name}{full_rel_path}: {exc}")
                    continue

            extracted = extract_text_from_bytes(raw_bytes, filename)
            if extracted.error:
                warnings.append(f"{share_name}{full_rel_path}: {extracted.error}")

            inspection_text = f"{filename}\n{extracted.text}".strip()
            pii_findings = analyze_text(inspection_text, regulatory_profile=self.regulatory_profile)
            if not pii_findings:
                continue

            last_write = float(getattr(item, "last_write_time", 0) or 0)
            age_days: Optional[int] = (
                max(0, int((now_ts - last_write) / 86400)) if last_write > 0 else None
            )
            has_clinical_health = any(
                f.entity_type == "PA_DATO_SENSIBLE_SALUD" for f in pii_findings
            )
            file_retention_violation = evaluate_retention_violation(
                self.regulatory_profile,
                age_days,
                is_clinical=has_clinical_health,
            )

            counters["pii_files"] += 1
            if file_retention_violation:
                counters["retention_violations"] += 1

            cedulas = [f for f in pii_findings if f.entity_type == "PA_IDENTIDAD_NATURAL"]
            emails = [f for f in pii_findings if f.entity_type == "EMAIL_PERSONAL"]
            passports = [f for f in pii_findings if f.entity_type == "PA_PASAPORTE"]
            sensitive_list = [f for f in pii_findings if f.is_sensitive]

            counters["cedulas"] += len(cedulas)
            counters["passports"] += len(passports)
            counters["emails"] += len(emails)
            counters["sensitive"] += len(sensitive_list)

            unc_path = f"\\\\{self.server_ip}\\{share_name}{full_rel_path.replace('/', '\\')}"
            source_type = (
                "OCR_IMAGE" if (ext in IMAGE_EXTENSIONS or extracted.ocr_used) else "SMB"
            )
            file_severity = (
                "CRÍTICO"
                if (sensitive_list or file_retention_violation or cedulas)
                else "ALTO"
            )

            findings_detail.append(
                {
                    "unc_path": unc_path,
                    "share": share_name,
                    "filename": filename,
                    "size_kb": round(item.file_size / 1024, 1),
                    "cedulas_found": [f.masked_value for f in cedulas[:5]],
                    "rucs_found": [],
                    "emails_found": [f.masked_value for f in emails[:5]],
                    "entity_types": sorted(list({f.entity_type for f in pii_findings})),
                    "cedula_count": len(cedulas),
                    "ruc_count": 0,
                    "email_count": len(emails),
                    "sensitive_count": len(sensitive_list),
                    "retention_age_days": age_days,
                    "retention_violation": file_retention_violation,
                    "ocr_used": extracted.ocr_used,
                    "severity": file_severity,
                }
            )

            # Group findings per entity_type for v2 FindingBatchPayload (strictly masked!)
            grouped: Dict[str, List[PiiFinding]] = {}
            for finding in pii_findings:
                grouped.setdefault(finding.entity_type, []).append(finding)

            for entity_type, items_of_type in grouped.items():
                first = items_of_type[0]
                any_sensitive = any(i.is_sensitive for i in items_of_type)
                ent_ret_violation = evaluate_retention_violation(
                    self.regulatory_profile,
                    age_days,
                    is_clinical=(entity_type == "PA_DATO_SENSIBLE_SALUD" or has_clinical_health),
                )
                findings_v2.append(
                    {
                        "source_type": source_type,
                        "repository_name": f"\\\\{self.server_ip}\\{share_name}",
                        "location_path": full_rel_path.lstrip("/"),
                        "entity_type": entity_type,
                        "masked_sample": first.masked_value,
                        "value_sha256": first.value_sha256,
                        "match_count": len(items_of_type),
                        "is_sensitive": any_sensitive,
                        "severity": compute_finding_severity(
                            entity_type, any_sensitive, ent_ret_violation
                        ),
                        "retention_age_days": age_days,
                        "retention_violation": ent_ret_violation,
                        "detected_at": detected_iso,
                    }
                )

    def _generate_fallback_simulation(
        self,
        remote_name: str,
        connection_reason: str,
        start_time: float,
    ) -> Dict[str, Any]:
        """
        Explicitly requested simulation mode: uses synthetic strings analyzed by panama-pii-py
        and emits strictly masked samples + SHA-256 hashes (is_simulated=True).
        """
        scan_id = f"smb-sim-{uuid.uuid4().hex[:10]}"
        detected_iso = datetime.now(timezone.utc).isoformat()
        simulated_samples = [
            {
                "share": "Planilla",
                "path": "/2017/Quincena_Historica_2017.xlsx",
                "size_kb": 428.4,
                "age_days": 3100,
                "content": "Colaborador cédula 8-888-1234 y 4-752-901, correo nomina@empresa-pa.example",
            },
            {
                "share": "Contratos",
                "path": "/Clientes_VIP/Contrato_Servicios_Fiduciarios_2026.pdf",
                "size_kb": 1840.0,
                "age_days": 95,
                "content": "Representante Legal cédula 8-714-2219 y E-8-104921, correo legal@fiduciaria-pty.example",
            },
            {
                "share": "Legal",
                "path": "/Litigios/Expediente_Laboral_2025.docx",
                "size_kb": 612.0,
                "age_days": 400,
                "content": "Paciente con cédula 3-702-1198, diagnóstico médico en expediente clínico",
            },
        ]

        findings_detail: List[Dict[str, Any]] = []
        findings_v2: List[Dict[str, Any]] = []
        total_cedulas = 0
        total_emails = 0
        sensitive_count = 0
        retention_violations = 0

        for item in simulated_samples:
            findings = analyze_text(item["content"], regulatory_profile=self.regulatory_profile)
            age_days = item["age_days"]
            has_clinical = any(f.entity_type == "PA_DATO_SENSIBLE_SALUD" for f in findings)
            ret_violation = evaluate_retention_violation(
                self.regulatory_profile, age_days, is_clinical=has_clinical
            )
            if ret_violation:
                retention_violations += 1

            cedulas = [f for f in findings if f.entity_type == "PA_IDENTIDAD_NATURAL"]
            emails = [f for f in findings if f.entity_type == "EMAIL_PERSONAL"]
            sens = [f for f in findings if f.is_sensitive]
            total_cedulas += len(cedulas)
            total_emails += len(emails)
            sensitive_count += len(sens)

            filename = item["path"].rsplit("/", 1)[-1]
            findings_detail.append(
                {
                    "unc_path": f"\\\\{self.server_ip}\\{item['share']}{item['path'].replace('/', '\\')}",
                    "share": item["share"],
                    "filename": filename,
                    "size_kb": item["size_kb"],
                    "cedulas_found": [f.masked_value for f in cedulas],
                    "rucs_found": [],
                    "emails_found": [f.masked_value for f in emails],
                    "entity_types": sorted(list({f.entity_type for f in findings})),
                    "cedula_count": len(cedulas),
                    "ruc_count": 0,
                    "email_count": len(emails),
                    "sensitive_count": len(sens),
                    "retention_age_days": age_days,
                    "retention_violation": ret_violation,
                    "ocr_used": False,
                    "severity": "CRÍTICO" if (sens or ret_violation or cedulas) else "ALTO",
                }
            )

            grouped: Dict[str, List[PiiFinding]] = {}
            for f in findings:
                grouped.setdefault(f.entity_type, []).append(f)

            for entity_type, items_of_type in grouped.items():
                first = items_of_type[0]
                any_sensitive = any(i.is_sensitive for i in items_of_type)
                ent_ret_violation = evaluate_retention_violation(
                    self.regulatory_profile,
                    age_days,
                    is_clinical=(entity_type == "PA_DATO_SENSIBLE_SALUD" or has_clinical),
                )
                findings_v2.append(
                    {
                        "source_type": "SMB",
                        "repository_name": f"\\\\{self.server_ip}\\{item['share']}",
                        "location_path": item["path"].lstrip("/"),
                        "entity_type": entity_type,
                        "masked_sample": first.masked_value or mask_pii_value("***"),
                        "value_sha256": first.value_sha256 or hash_pii_sha256(filename),
                        "match_count": len(items_of_type),
                        "is_sensitive": any_sensitive,
                        "severity": compute_finding_severity(
                            entity_type, any_sensitive, ent_ret_violation
                        ),
                        "retention_age_days": age_days,
                        "retention_violation": ent_ret_violation,
                        "detected_at": detected_iso,
                    }
                )

        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return {
            "scan_id": scan_id,
            "tenant_id": self.tenant_id,
            "regulatory_profile": self.regulatory_profile,
            "target_ip": self.server_ip,
            "server_name": f"WIN-SRV-FS01 ({remote_name})",
            "auth_mode": "Guest/Anonymous (Simulación Explícita)",
            "guest_access_allowed": True,
            "is_simulated": True,
            "simulation_reason": connection_reason,
            "total_shares": 3,
            "critical_shares_found": [
                f"\\\\{self.server_ip}\\Planilla",
                f"\\\\{self.server_ip}\\Contratos",
                f"\\\\{self.server_ip}\\Legal",
            ],
            "total_office_pdf_files": 42,
            "files_with_pii_count": len(findings_detail),
            "cedula_matches_count": total_cedulas,
            "ruc_matches_count": 0,
            "email_matches_count": total_emails,
            "sensitive_findings_count": sensitive_count,
            "retention_violations_count": retention_violations,
            "findings_detail": findings_detail,
            "findings_v2": findings_v2,
            "finding_batch_payload": {
                "tenant_id": self.tenant_id,
                "scan_id": scan_id,
                "scanner_layer": "SMB_CONNECTOR",
                "is_simulated": True,
                "total_assets_scanned": 42,
                "scan_duration_ms": elapsed_ms,
                "findings": findings_v2,
            },
            "warnings": [],
            "scan_duration_ms": elapsed_ms,
        }
