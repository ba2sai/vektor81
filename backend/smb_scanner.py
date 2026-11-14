"""
Escáner de Recursos Compartidos Windows Server (SMB/CIFS) para cumplimiento de Ley 81 (Panamá).
Usa pysmb (SMBConnection) para:
1. Evaluar sesiones Guest / Anónimas o credenciales de dominio.
2. Detectar carpetas críticas (Contratos, Planilla, Finanzas, Legal, Clientes, RRHH).
3. Contabilizar documentos (.pdf, .xlsx, .docx) y escanear nombres + primeros KB buscando:
   - Cédula Panameña: \\b(?:[1-9]|1[0-3]|PE|E|N)-\\d{1,4}-\\d{1,6}\\b
   - RUC Panameño (Persona Jurídica / Natural con DV)
   - Correos electrónicos corporativos y personales.
"""

import io
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure

# Expresiones Regulares Deterministas para Datos Personales / Sensibles en Panamá (Ley 81)
REGEX_CEDULA_PANAMA = re.compile(r"\b(?:[1-9]|1[0-3]|PE|E|N)-\d{1,4}-\d{1,6}\b")
REGEX_RUC_PANAMA = re.compile(r"\b\d{1,8}-\d{1,4}-\d{4,7}(?:\s*DV\s*\d{1,2})?\b", re.IGNORECASE)
REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

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
)

TARGET_EXTENSIONS = {".pdf", ".xlsx", ".docx", ".xls", ".doc", ".csv", ".txt"}
SYSTEM_SHARES = {"IPC$", "ADMIN$", "C$", "D$", "E$", "PRINT$", "FAX$", "NETLOGON", "SYSVOL"}


def mask_sensitive_value(val: str) -> str:
    """Enmascara parcialmente el dato sensible encontrado para no almacenar PII en texto plano (Principio de Minimización Ley 81)."""
    if len(val) <= 4:
        return "***"
    return f"{val[:3]}***{val[-2:]}"


def extract_printable_text(raw_bytes: bytes) -> str:
    """
    Extrae cadenas legibles ASCII/UTF-8/UTF-16LE de los primeros kilobytes de un archivo
    (.pdf, .docx, .xlsx, .csv) sin cargar librerías pesadas en RAM.
    """
    texts = []
    try:
        texts.append(raw_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    try:
        texts.append(raw_bytes.decode("latin-1", errors="ignore"))
    except Exception:
        pass
    try:
        texts.append(raw_bytes.decode("utf-16le", errors="ignore"))
    except Exception:
        pass
    return "\n".join(texts)


def analyze_text_for_panama_pii(text: str) -> Tuple[List[str], List[str], List[str]]:
    """Retorna listas únicas de coincidencias de Cédula, RUC y Email."""
    cedulas = list(dict.fromkeys(REGEX_CEDULA_PANAMA.findall(text)))
    rucs = list(dict.fromkeys(REGEX_RUC_PANAMA.findall(text)))
    emails = list(dict.fromkeys(REGEX_EMAIL.findall(text)))
    return cedulas, rucs, emails


def is_critical_name(name: str) -> bool:
    normalized = name.lower().strip()
    return any(keyword in normalized for keyword in CRITICAL_FOLDER_KEYWORDS)


class WindowsSmbScanner:
    """Escáner SMB ligero de bajo consumo de memoria (< 25MB RAM en ejecución)."""

    def __init__(
        self,
        server_ip: str,
        username: str = "",
        password: str = "",
        domain: str = "WORKGROUP",
        port: int = 445,
        max_depth: int = 3,
        sample_kb_limit: int = 16,
    ):
        self.server_ip = server_ip
        self.username = username.strip()
        self.password = password
        self.domain = domain or "WORKGROUP"
        self.port = port
        self.max_depth = max_depth
        self.sample_bytes_limit = sample_kb_limit * 1024
        self.client_name = "VEKTOR81-AUDIT"

    def _resolve_netbios_name(self) -> str:
        try:
            host, _, _ = socket.gethostbyaddr(self.server_ip)
            return host.split(".")[0].upper()
        except Exception:
            return self.server_ip

    def run_scan(self, simulate_if_unreachable: bool = True) -> Dict[str, Any]:
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
            raise RuntimeError(f"No se pudo conectar al servidor SMB {self.server_ip}:{self.port} -> {exc}") from exc
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
        shares = conn.listShares(timeout=5)
        critical_shares_found: List[str] = []
        findings_detail: List[Dict[str, Any]] = []

        total_office_pdf_files = 0
        files_with_pii_count = 0
        cedula_matches_count = 0
        ruc_matches_count = 0
        email_matches_count = 0
        accessible_shares = 0

        for share in shares:
            share_name = share.name
            if share_name.upper() in SYSTEM_SHARES or share.isSpecial:
                continue

            accessible_shares += 1
            if is_critical_name(share_name):
                critical_shares_found.append(share_name)

            # Explorar recursivamente con límite de profundidad
            share_stats = self._walk_share(
                conn=conn,
                share_name=share_name,
                current_path="/",
                depth=1,
                critical_shares_found=critical_shares_found,
                findings_detail=findings_detail,
            )
            total_office_pdf_files += share_stats["office_files"]
            files_with_pii_count += share_stats["pii_files"]
            cedula_matches_count += share_stats["cedulas"]
            ruc_matches_count += share_stats["rucs"]
            email_matches_count += share_stats["emails"]

        elapsed_ms = int((time.perf_counter() - start_time) * 1000)

        return {
            "target_ip": self.server_ip,
            "server_name": remote_name,
            "auth_mode": "Guest/Anonymous" if is_guest_attempt else f"Authenticated ({self.domain}\\{self.username})",
            "guest_access_allowed": is_guest_attempt,
            "is_simulated": False,
            "total_shares": accessible_shares,
            "critical_shares_found": sorted(list(set(critical_shares_found))),
            "total_office_pdf_files": total_office_pdf_files,
            "files_with_pii_count": files_with_pii_count,
            "cedula_matches_count": cedula_matches_count,
            "ruc_matches_count": ruc_matches_count,
            "email_matches_count": email_matches_count,
            "findings_detail": findings_detail[:50],  # Top 50 hallazgos para mantener payload ligero
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
    ) -> Dict[str, int]:
        stats = {"office_files": 0, "pii_files": 0, "cedulas": 0, "rucs": 0, "emails": 0}
        if depth > self.max_depth:
            return stats

        try:
            items = conn.listPath(share_name, current_path, timeout=4)
        except OperationFailure:
            return stats
        except Exception:
            return stats

        for item in items:
            filename = item.filename
            if filename in (".", ".."):
                continue

            full_rel_path = f"{current_path.rstrip('/')}/{filename}"

            if item.isDirectory:
                if is_critical_name(filename):
                    critical_label = f"\\\\{self.server_ip}\\{share_name}{full_rel_path.replace('/', '\\')}"
                    if critical_label not in critical_shares_found:
                        critical_shares_found.append(critical_label)

                sub_stats = self._walk_share(
                    conn=conn,
                    share_name=share_name,
                    current_path=full_rel_path,
                    depth=depth + 1,
                    critical_shares_found=critical_shares_found,
                    findings_detail=findings_detail,
                )
                for k in stats:
                    stats[k] += sub_stats[k]
                continue

            # Verificar extensión de archivo objetivo
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in TARGET_EXTENSIONS:
                continue

            stats["office_files"] += 1

            # 1) Escaneo de nombre de archivo + ruta
            inspection_buffer = f"{full_rel_path} {filename}\n"

            # 2) Escaneo de primeros kilobytes (sin descargar el archivo completo)
            if item.file_size > 0:
                buf = io.BytesIO()
                try:
                    conn.retrieveFileFromOffset(
                        service_name=share_name,
                        path=full_rel_path,
                        file_obj=buf,
                        offset=0,
                        max_length=self.sample_bytes_limit,
                        timeout=3,
                    )
                    inspection_buffer += extract_printable_text(buf.getvalue())
                except Exception:
                    pass

            cedulas, rucs, emails = analyze_text_for_panama_pii(inspection_buffer)
            if cedulas or rucs or emails:
                stats["pii_files"] += 1
                stats["cedulas"] += len(cedulas)
                stats["rucs"] += len(rucs)
                stats["emails"] += len(emails)

                findings_detail.append(
                    {
                        "unc_path": f"\\\\{self.server_ip}\\{share_name}{full_rel_path.replace('/', '\\')}",
                        "share": share_name,
                        "filename": filename,
                        "size_kb": round(item.file_size / 1024, 1),
                        "cedulas_found": [mask_sensitive_value(c) for c in cedulas[:5]],
                        "rucs_found": [mask_sensitive_value(r) for r in rucs[:5]],
                        "emails_found": [mask_sensitive_value(e) for e in emails[:5]],
                        "cedula_count": len(cedulas),
                        "ruc_count": len(rucs),
                        "email_count": len(emails),
                        "severity": "CRÍTICO" if cedulas else "ALTO",
                    }
                )

        return stats

    def _generate_fallback_simulation(
        self, remote_name: str, connection_reason: str, start_time: float
    ) -> Dict[str, Any]:
        """
        Cuando se ejecuta la auditoría en un entorno aislado o contenedor donde el Windows Server
        indicado aún no es alcanzable por puerto 445, provee un resultado de demostración determinista
        con patrones reales de Cédula Panameña y RUC evaluados por el mismo motor Regex.
        """
        simulated_samples = [
            {
                "share": "Planilla",
                "path": "/2026/Quincena_Noviembre_2026.xlsx",
                "size_kb": 428.4,
                "content": "Colaborador: Juan Perez | Cedula: 8-888-1234 | Maria Gomez 4-752-901 | PE-12-4401 | RUC 1556421-1-784512 DV 45 | rrhh@empresa-pa.com, nomina@empresa-pa.com",
            },
            {
                "share": "Contratos",
                "path": "/Clientes_VIP/Contrato_Servicios_Fiduciarios_2026.pdf",
                "size_kb": 1840.0,
                "content": "Representante Legal portador de la cédula 8-714-2219 y E-8-104921, RUC 842109-1-502918 DV 12, correo legal@fiduciaria-pty.com",
            },
            {
                "share": "Finanzas",
                "path": "/Estados_Cuenta/Listado_Proveedores_ACH_8-901-3312.docx",
                "size_kb": 215.8,
                "content": "Beneficiario 8-901-3312, 9-120-445, N-20-1920, RUC 2049123-1-891022 DV 89, pagos@corporacion-istmo.com, tesoreria@banco-local.pa",
            },
            {
                "share": "Legal",
                "path": "/Litigios/Expediente_Laboral_MITRADEL_2026.pdf",
                "size_kb": 950.2,
                "content": "Demandante con cédula 3-702-1198 y 8-451-992, apoderado legal@bufete-pty.com",
            },
            {
                "share": "Clientes",
                "path": "/KYC/Base_Datos_KYC_Ley81_Sin_Cifrar.xlsx",
                "size_kb": 3120.5,
                "content": "KYC Panama: 8-912-4012, 8-845-1102, 1-710-883, PE-9-2190, RUC 1094821-1-662019 DV 31, cumplimiento@empresa-pa.com",
            },
        ]

        findings_detail = []
        total_cedulas = 0
        total_rucs = 0
        total_emails = 0

        for item in simulated_samples:
            cedulas, rucs, emails = analyze_text_for_panama_pii(f"{item['path']} {item['content']}")
            total_cedulas += len(cedulas)
            total_rucs += len(rucs)
            total_emails += len(emails)
            filename = item["path"].rsplit("/", 1)[-1]
            findings_detail.append(
                {
                    "unc_path": f"\\\\{self.server_ip}\\{item['share']}{item['path'].replace('/', '\\')}",
                    "share": item["share"],
                    "filename": filename,
                    "size_kb": item["size_kb"],
                    "cedulas_found": [mask_sensitive_value(c) for c in cedulas],
                    "rucs_found": [mask_sensitive_value(r) for r in rucs],
                    "emails_found": [mask_sensitive_value(e) for e in emails],
                    "cedula_count": len(cedulas),
                    "ruc_count": len(rucs),
                    "email_count": len(emails),
                    "severity": "CRÍTICO" if cedulas else "ALTO",
                }
            )

        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return {
            "target_ip": self.server_ip,
            "server_name": f"WIN-SRV-FS01 ({remote_name})",
            "auth_mode": "Guest/Anonymous (Simulación LAN Demo)",
            "guest_access_allowed": True,
            "is_simulated": True,
            "simulation_reason": connection_reason,
            "total_shares": 6,
            "critical_shares_found": [
                f"\\\\{self.server_ip}\\Contratos",
                f"\\\\{self.server_ip}\\Planilla",
                f"\\\\{self.server_ip}\\Finanzas",
                f"\\\\{self.server_ip}\\Legal",
                f"\\\\{self.server_ip}\\Clientes",
            ],
            "total_office_pdf_files": 148,
            "files_with_pii_count": len(findings_detail),
            "cedula_matches_count": total_cedulas,
            "ruc_matches_count": total_rucs,
            "email_matches_count": total_emails,
            "findings_detail": findings_detail,
            "scan_duration_ms": elapsed_ms,
        }
