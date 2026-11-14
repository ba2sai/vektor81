"""
API Principal FastAPI para Vektor81: "Shadow AI & Ley 81 Audit Appliance".
Diseñado para ejecución 100% local en mini-servidor Linux sin GPU (< 500MB RAM).

Módulos incluidos:
1. POST /api/v1/ingest       -> Ingesta desde agente PowerShell en PCs Windows.
2. POST /api/v1/scan-smb     -> Escáner de Windows Server SMB/CIFS buscando PII Panameña (Cédula, RUC, Email).
3. GET  /api/v1/dns-stats    -> Conector AdGuard Home (/control/querylog) contra diccionario de 150+ dominios IA.
4. GET  /api/v1/report/pdf   -> Algoritmo Score de Riesgo Ley 81 + Compilación de Informe Ejecutivo PDF (WeasyPrint).
5. GET  /api/v1/dashboard    -> Consolidado de KPIs y telemetría para el Frontend React.
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from models import (
    DnsAuditSnapshot,
    EndpointAsset,
    EndpointIngestLog,
    EndpointIngestRequest,
    SessionLocal,
    SmbScanRequest,
    SmbScanResult,
    init_db,
)
from report_generator import (
    REPORT_HTML_TEMPLATE,
    calculate_ley81_risk_score,
    generate_executive_pdf_bytes,
)
from smb_scanner import WindowsSmbScanner

app = FastAPI(
    title="Vektor81 — Shadow AI & Ley 81 Audit Appliance",
    description="Motor de auditoría local determinista para Gobernanza de IA y Protección de Datos Personales (Ley 81 de Panamá).",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Variables de entorno para integración con AdGuard Home en la red local
ADGUARD_BASE_URL = os.getenv("ADGUARD_URL", "http://adguard:3000")
ADGUARD_USER = os.getenv("ADGUARD_USER", "admin")
ADGUARD_PASS = os.getenv("ADGUARD_PASS", "")

AI_DOMAINS_FILE = Path(__file__).parent / "ai_domains.json"


def load_ai_domains_dictionary() -> Dict[str, str]:
    """Carga el diccionario local de 150+ dominios de Shadow AI y su categoría."""
    if AI_DOMAINS_FILE.exists():
        with open(AI_DOMAINS_FILE, "r", encoding="utf-8") as f:
            return {k.lower().strip(): v for k, v in json.load(f).items()}
    return {
        "chatgpt.com": "LLM Conversacional",
        "claude.ai": "LLM Conversacional",
        "deepseek.com": "LLM Conversacional",
        "ilovepdf.com": "Procesamiento PDF / Docs",
        "perplexity.ai": "Buscador IA",
    }


AI_DOMAINS_MAP: Dict[str, str] = load_ai_domains_dictionary()


def match_shadow_ai_domain(qname: str) -> Optional[Tuple[str, str]]:
    """Verifica si un FQDN consultado por DNS coincide con uno de los 150+ dominios de IA."""
    clean = qname.lower().strip().rstrip(".")
    if clean in AI_DOMAINS_MAP:
        return clean, AI_DOMAINS_MAP[clean]
    for registered_domain, category in AI_DOMAINS_MAP.items():
        if clean.endswith("." + registered_domain):
            return registered_domain, category
    return None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    # Si la base de datos está vacía en el primer arranque, carga una semilla inicial realista
    # para que el appliance sea inmediatamente verificable en demostraciones.
    db = SessionLocal()
    try:
        if db.query(EndpointAsset).count() == 0:
            _seed_initial_audit_data(db)
    finally:
        db.close()


# =====================================================================
# MÓDULO 1: INGESTA DE ENDPOINTS WINDOWS (POST /api/v1/ingest)
# =====================================================================

@app.post("/api/v1/ingest", tags=["Módulo 1: Ingesta de Endpoints"])
def ingest_endpoint_audit(payload: EndpointIngestRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Recibe el JSON enviado por el script PowerShell de las PCs Windows:
    (`hostname`, `username`, `shadow_ai_dns_hits`, `risky_extensions`, `box_audit`).
    Guarda el historial en SQLite y actualiza el inventario de máquinas auditadas.
    """
    hostname_norm = payload.hostname.strip().upper()
    total_dns_hits = sum(item.count for item in payload.shadow_ai_dns_hits)
    all_urls_exts = [ext for ext in payload.risky_extensions if ext.has_all_urls or "<all_urls>" in ext.permissions]
    box_exposed = payload.box_audit.sensitive_files_count if not payload.box_audit.dlp_enabled else 0

    # Cálculo rápido de riesgo del endpoint individual (0-100)
    ep_risk = min(
        100.0,
        round((total_dns_hits * 2.5) + (len(all_urls_exts) * 18.0) + (box_exposed * 1.5), 1),
    )

    asset = db.query(EndpointAsset).filter(EndpointAsset.hostname == hostname_norm).first()
    if not asset:
        asset = EndpointAsset(
            hostname=hostname_norm,
            username=payload.username,
            ip_address=payload.ip_address,
            os_version=payload.os_version or "Windows 11 Pro",
        )
        db.add(asset)
        db.flush()
    else:
        asset.username = payload.username
        if payload.ip_address:
            asset.ip_address = payload.ip_address
        if payload.os_version:
            asset.os_version = payload.os_version
        asset.last_seen = datetime.now(timezone.utc)

    asset.dns_hits_count = total_dns_hits
    asset.risky_extensions_count = len(all_urls_exts)
    asset.box_exposed_files = payload.box_audit.sensitive_files_count
    asset.box_dlp_active = payload.box_audit.dlp_enabled
    asset.endpoint_risk_score = ep_risk

    # Enriquecer categoría de cada dominio con nuestro diccionario local de 150 dominios
    enriched_dns_hits = []
    for hit in payload.shadow_ai_dns_hits:
        matched = match_shadow_ai_domain(hit.domain)
        category = matched[1] if matched else (hit.category or "IA / Cloud No Autorizado")
        enriched_dns_hits.append(
            {
                "domain": hit.domain.lower(),
                "count": hit.count,
                "category": category,
                "last_timestamp": hit.last_timestamp,
            }
        )

    ingest_log = EndpointIngestLog(
        asset_id=asset.id,
        hostname=hostname_norm,
        username=payload.username,
        shadow_ai_dns_hits=enriched_dns_hits,
        risky_extensions=[ext.model_dump() for ext in payload.risky_extensions],
        box_audit=payload.box_audit.model_dump(),
    )
    db.add(ingest_log)
    db.commit()
    db.refresh(asset)

    return {
        "status": "ingested",
        "asset_id": asset.id,
        "hostname": asset.hostname,
        "endpoint_risk_score": asset.endpoint_risk_score,
        "summary": {
            "dns_hits_count": asset.dns_hits_count,
            "risky_extensions_count": asset.risky_extensions_count,
            "box_exposed_files": asset.box_exposed_files,
            "box_dlp_active": asset.box_dlp_active,
        },
    }


# =====================================================================
# MÓDULO 2: ESCÁNER WINDOWS SERVER SMB (POST /api/v1/scan-smb)
# =====================================================================

@app.post("/api/v1/scan-smb", tags=["Módulo 2: Escáner Windows Server SMB"])
def scan_windows_smb_server(req: SmbScanRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Audita recursos compartidos en un Windows Server vía SMB/CIFS (pysmb).
    Identifica carpetas críticas (Contratos, Planilla, Finanzas, Legal, Clientes),
    cuenta archivos (.pdf, .xlsx, .docx) y aplica expresiones regulares de Cédula Panameña, RUC y Email.
    """
    scanner = WindowsSmbScanner(
        server_ip=req.server_ip,
        username=req.username or "",
        password=req.password or "",
        domain=req.domain or "WORKGROUP",
        port=req.port,
        max_depth=req.max_depth,
        sample_kb_limit=req.sample_kb_limit,
    )

    try:
        result_data = scanner.run_scan(simulate_if_unreachable=req.simulate_if_unreachable)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    smb_record = SmbScanResult(
        target_ip=result_data["target_ip"],
        server_name=result_data["server_name"],
        auth_mode=result_data["auth_mode"],
        guest_access_allowed=result_data["guest_access_allowed"],
        total_shares=result_data["total_shares"],
        critical_shares_found=result_data["critical_shares_found"],
        total_office_pdf_files=result_data["total_office_pdf_files"],
        files_with_pii_count=result_data["files_with_pii_count"],
        cedula_matches_count=result_data["cedula_matches_count"],
        ruc_matches_count=result_data["ruc_matches_count"],
        email_matches_count=result_data["email_matches_count"],
        findings_detail=result_data["findings_detail"],
        scan_duration_ms=result_data["scan_duration_ms"],
    )
    db.add(smb_record)
    db.commit()
    db.refresh(smb_record)

    return {
        "scan_id": smb_record.id,
        "created_at": smb_record.created_at.isoformat(),
        **result_data,
    }


# =====================================================================
# MÓDULO 3: CONECTOR ADGUARD HOME (GET /api/v1/dns-stats)
# =====================================================================

@app.get("/api/v1/dns-stats", tags=["Módulo 3: Conector AdGuard Home"])
async def get_adguard_dns_stats(
    limit: int = Query(default=500, ge=50, le=2000),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Consulta `/control/querylog` de AdGuard Home en la red local y filtra contra el diccionario
    JSON local de 150+ dominios de IA, agrupando por IP de origen y categoría de herramienta.
    Si AdGuard Home no está accesible aún, combina la telemetría DNS ingerida de los endpoints.
    """
    by_client_ip: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"total_hits": 0, "domains": defaultdict(int)})
    by_category: Dict[str, int] = defaultdict(int)
    by_domain: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "category": ""})
    total_inspected = 0
    adguard_live = False

    # 1. Intentar consulta en vivo al endpoint /control/querylog de AdGuard Home
    try:
        auth = (ADGUARD_USER, ADGUARD_PASS) if ADGUARD_PASS else None
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                f"{ADGUARD_BASE_URL.rstrip('/')}/control/querylog",
                params={"limit": limit},
                auth=auth,
            )
            if resp.status_code == 200:
                adguard_live = True
                payload = resp.json()
                entries = payload.get("data", [])
                total_inspected = len(entries)
                for entry in entries:
                    question = entry.get("question", {})
                    qname = question.get("name", "")
                    client_ip = entry.get("client", "unknown")
                    matched = match_shadow_ai_domain(qname)
                    if matched:
                        canonical_dom, category = matched
                        by_client_ip[client_ip]["total_hits"] += 1
                        by_client_ip[client_ip]["domains"][canonical_dom] += 1
                        by_category[category] += 1
                        by_domain[canonical_dom]["count"] += 1
                        by_domain[canonical_dom]["category"] = category
    except Exception:
        adguard_live = False

    # 2. Complementar con los registros DNS reportados por los agentes de Endpoints en SQLite
    latest_logs = db.query(EndpointIngestLog).order_by(EndpointIngestLog.created_at.desc()).limit(50).all()
    seen_hosts = set()
    for log in latest_logs:
        if log.hostname in seen_hosts:
            continue
        seen_hosts.add(log.hostname)
        asset = db.query(EndpointAsset).filter(EndpointAsset.id == log.asset_id).first()
        client_key = f"{asset.ip_address or 'LAN'} ({log.hostname})" if asset else log.hostname

        for hit in log.shadow_ai_dns_hits or []:
            dom = hit.get("domain", "").lower()
            cnt = int(hit.get("count", 1))
            matched = match_shadow_ai_domain(dom)
            canonical_dom = matched[0] if matched else dom
            category = matched[1] if matched else hit.get("category", "LLM Conversacional")

            total_inspected += cnt * 8
            by_client_ip[client_key]["total_hits"] += cnt
            by_client_ip[client_key]["domains"][canonical_dom] += cnt
            by_category[category] += cnt
            by_domain[canonical_dom]["count"] += cnt
            by_domain[canonical_dom]["category"] = category

    # Formatear respuesta limpia
    formatted_clients = [
        {
            "client": client,
            "total_hits": info["total_hits"],
            "domains": [{"domain": d, "count": c} for d, c in sorted(info["domains"].items(), key=lambda x: -x[1])],
        }
        for client, info in sorted(by_client_ip.items(), key=lambda x: -x[1]["total_hits"])
    ]

    formatted_domains = [
        {"domain": dom, "count": info["count"], "category": info["category"]}
        for dom, info in sorted(by_domain.items(), key=lambda x: -x[1]["count"])
    ]

    formatted_categories = [
        {"category": cat, "count": count}
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1])
    ]

    total_shadow_hits = sum(item["count"] for item in formatted_domains)

    # Guardar snapshot en SQLite
    snapshot = DnsAuditSnapshot(
        total_queries_inspected=total_inspected,
        shadow_ai_hits_total=total_shadow_hits,
        by_client_ip={c["client"]: c for c in formatted_clients},
        by_category=dict(by_category),
        by_domain={d["domain"]: d["count"] for d in formatted_domains},
    )
    db.add(snapshot)
    db.commit()

    return {
        "adguard_live_connected": adguard_live,
        "adguard_endpoint": f"{ADGUARD_BASE_URL}/control/querylog",
        "dictionary_domains_loaded": len(AI_DOMAINS_MAP),
        "total_queries_inspected": total_inspected,
        "shadow_ai_hits_total": total_shadow_hits,
        "by_client_ip": formatted_clients,
        "by_category": formatted_categories,
        "top_domains": formatted_domains[:15],
    }


# =====================================================================
# MÓDULO 4: SCORE DE RIESGO LEY 81 Y GENERADOR PDF (GET /api/v1/report/pdf)
# =====================================================================

def _build_audit_context(db: Session) -> Dict[str, Any]:
    """Construye el contexto unificado para el Dashboard y el Generador PDF."""
    endpoints = db.query(EndpointAsset).order_by(EndpointAsset.endpoint_risk_score.desc()).all()
    latest_smb = db.query(SmbScanResult).order_by(SmbScanResult.created_at.desc()).first()

    # Consolidar dominios Shadow AI desde los últimos logs de cada endpoint
    domain_counter: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "category": "LLM Conversacional"})
    all_urls_extensions_total = 0
    box_unprotected_files_total = 0
    detailed_endpoints = []

    for ep in endpoints:
        all_urls_extensions_total += ep.risky_extensions_count
        if not ep.box_dlp_active:
            box_unprotected_files_total += ep.box_exposed_files

        latest_log = (
            db.query(EndpointIngestLog)
            .filter(EndpointIngestLog.asset_id == ep.id)
            .order_by(EndpointIngestLog.created_at.desc())
            .first()
        )
        exts_list = latest_log.risky_extensions if latest_log else []
        box_info = latest_log.box_audit if latest_log else {}

        for hit in (latest_log.shadow_ai_dns_hits if latest_log else []):
            dom = hit.get("domain", "").lower()
            cnt = int(hit.get("count", 1))
            matched = match_shadow_ai_domain(dom)
            cat = matched[1] if matched else hit.get("category", "LLM Conversacional")
            domain_counter[dom]["count"] += cnt
            domain_counter[dom]["category"] = cat

        detailed_endpoints.append(
            {
                "id": ep.id,
                "hostname": ep.hostname,
                "username": ep.username,
                "ip_address": ep.ip_address,
                "os_version": ep.os_version,
                "last_seen": ep.last_seen.isoformat() if ep.last_seen else None,
                "dns_hits_count": ep.dns_hits_count,
                "risky_extensions_count": ep.risky_extensions_count,
                "box_exposed_files": ep.box_exposed_files,
                "box_dlp_active": ep.box_dlp_active,
                "endpoint_risk_score": ep.endpoint_risk_score,
                "risky_extensions": exts_list,
                "box_audit": box_info,
            }
        )

    top_ai_domains = [
        {"domain": dom, "count": info["count"], "category": info["category"]}
        for dom, info in sorted(domain_counter.items(), key=lambda x: -x[1]["count"])
    ]

    total_shadow_ai_hits = sum(d["count"] for d in top_ai_domains)
    smb_pii_files = latest_smb.files_with_pii_count if latest_smb else 0
    smb_guest_allowed = latest_smb.guest_access_allowed if latest_smb else False

    risk_evaluation = calculate_ley81_risk_score(
        total_shadow_ai_hits=total_shadow_ai_hits,
        unique_ai_domains_count=len(top_ai_domains),
        smb_pii_files_count=smb_pii_files,
        smb_guest_allowed=smb_guest_allowed,
        box_unprotected_files_count=box_unprotected_files_total,
        all_urls_extensions_count=all_urls_extensions_total,
        audited_endpoints_count=len(endpoints),
    )

    smb_dict = None
    if latest_smb:
        smb_dict = {
            "id": latest_smb.id,
            "target_ip": latest_smb.target_ip,
            "server_name": latest_smb.server_name,
            "auth_mode": latest_smb.auth_mode,
            "guest_access_allowed": latest_smb.guest_access_allowed,
            "total_shares": latest_smb.total_shares,
            "critical_shares_found": latest_smb.critical_shares_found,
            "total_office_pdf_files": latest_smb.total_office_pdf_files,
            "files_with_pii_count": latest_smb.files_with_pii_count,
            "cedula_matches_count": latest_smb.cedula_matches_count,
            "ruc_matches_count": latest_smb.ruc_matches_count,
            "email_matches_count": latest_smb.email_matches_count,
            "findings_detail": latest_smb.findings_detail,
            "created_at": latest_smb.created_at.isoformat(),
        }

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "kpis": {
            "audited_endpoints": len(endpoints),
            "shadow_ai_events": total_shadow_ai_hits,
            "exposed_files_smb_box": smb_pii_files + box_unprotected_files_total,
            "global_risk_score": risk_evaluation["total_score"],
        },
        "risk": risk_evaluation,
        "endpoints": detailed_endpoints,
        "top_ai_domains": top_ai_domains[:12],
        "latest_smb": smb_dict,
    }


@app.get("/api/v1/report/pdf", tags=["Módulo 4: Score Ley 81 y Generador PDF"])
def generate_ley81_pdf_report(
    format: str = Query(default="pdf", pattern="^(pdf|html)$"),
    db: Session = Depends(get_db),
):
    """
    Calcula el Score de Riesgo Ley 81 (40% Shadow AI, 30% SMB/Box sin DLP, 30% Extensiones <all_urls>)
    y compila el Informe Ejecutivo en PDF con WeasyPrint (o vista previa HTML si `format=html`).
    """
    context = _build_audit_context(db)

    if format == "html":
        from jinja2 import BaseLoader, Environment

        env = Environment(loader=BaseLoader(), autoescape=True)
        html_str = env.from_string(REPORT_HTML_TEMPLATE).render(**context)
        return HTMLResponse(content=html_str)

    try:
        pdf_bytes = generate_executive_pdf_bytes(context)
        filename = f"Informe_Ejecutivo_Ley81_Panamá_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error al generar el PDF con WeasyPrint: {exc}. Puede previsualizar el HTML en /api/v1/report/pdf?format=html",
        )


# =====================================================================
# MÓDULO 5: ENDPOINT CONSOLIDADO PARA EL DASHBOARD WEB LOCAL
# =====================================================================

@app.get("/api/v1/dashboard", tags=["Módulo 5: Dashboard Web Local"])
def get_dashboard_overview(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Retorna todos los KPIs, gráficas de Shadow AI, tabla de endpoints y estado SMB en una sola llamada."""
    return _build_audit_context(db)


@app.get("/api/v1/agent/powershell", tags=["Módulo 1: Ingesta de Endpoints"])
def download_powershell_collector() -> Response:
    """Permite descargar directamente desde el Dashboard el agente recolector PowerShell (.ps1)."""
    candidates = [
        Path("/app/agents/Vektor81-EndpointCollector.ps1"),
        Path(__file__).resolve().parent.parent / "agents" / "Vektor81-EndpointCollector.ps1",
    ]
    for path in candidates:
        if path.exists():
            content = path.read_text(encoding="utf-8")
            return Response(
                content=content,
                media_type="text/plain; charset=utf-8",
                headers={
                    "Content-Disposition": 'attachment; filename="Vektor81-EndpointCollector.ps1"'
                },
            )
    raise HTTPException(status_code=404, detail="Script PowerShell no encontrado.")


# =====================================================================
# SEMILLA DETERMINISTA INICIAL PARA DEMOSTRACIÓN INMEDIATA
# =====================================================================

def _seed_initial_audit_data(db: Session) -> None:
    """Puebla datos iniciales realistas de una empresa en Panamá para que el Dashboard arranque con métricas."""
    sample_endpoints = [
        EndpointIngestRequest(
            hostname="PC-LEGAL-01",
            username="CORP\\cmedina",
            ip_address="192.168.10.21",
            os_version="Windows 11 Pro 23H2",
            shadow_ai_dns_hits=[
                {"domain": "chatgpt.com", "count": 34, "category": "LLM Conversacional"},
                {"domain": "ilovepdf.com", "count": 19, "category": "Procesamiento PDF / Docs"},
                {"domain": "chatpdf.com", "count": 11, "category": "Análisis Documental IA"},
                {"domain": "deepl.com", "count": 8, "category": "Traducción Cloud sin DLP"},
            ],
            risky_extensions=[
                {
                    "extension_id": "jiaopkpbeabcdefghijklmno",
                    "name": "Monica - Your AI Copilot & PDF Reader",
                    "browser": "Chrome",
                    "permissions": ["<all_urls>", "tabs", "webRequest", "storage"],
                    "has_all_urls": True,
                },
                {
                    "extension_id": "harpaaiext001928192",
                    "name": "HARPA AI Automation Agent",
                    "browser": "Edge",
                    "permissions": ["<all_urls>", "activeTab", "cookies"],
                    "has_all_urls": True,
                },
            ],
            box_audit={
                "installed": True,
                "sync_path": "C:\\Users\\cmedina\\Box\\Departamento_Legal",
                "total_synced_files": 340,
                "sensitive_files_count": 28,
                "dlp_enabled": False,
                "sample_files": [
                    "Contrato_Fideicomiso_Inmobiliario_2026.docx",
                    "Pacto_Social_Inversiones_Balboa.pdf",
                ],
            },
        ),
        EndpointIngestRequest(
            hostname="PC-PLANILLA-02",
            username="CORP\\lcastillo",
            ip_address="192.168.10.34",
            os_version="Windows 10 Pro 22H2",
            shadow_ai_dns_hits=[
                {"domain": "claude.ai", "count": 22, "category": "LLM Conversacional"},
                {"domain": "smallpdf.com", "count": 14, "category": "Procesamiento PDF / Docs"},
                {"domain": "julius.ai", "count": 9, "category": "Análisis de Datos / Excel IA"},
            ],
            risky_extensions=[
                {
                    "extension_id": "sideraiext9918273",
                    "name": "Sider: ChatGPT Sidebar + Vision",
                    "browser": "Chrome",
                    "permissions": ["<all_urls>", "clipboardRead", "tabs"],
                    "has_all_urls": True,
                }
            ],
            box_audit={
                "installed": True,
                "sync_path": "C:\\Users\\lcastillo\\Box\\RRHH_Planillas_SIPE",
                "total_synced_files": 190,
                "sensitive_files_count": 19,
                "dlp_enabled": False,
                "sample_files": [
                    "Planilla_SIPE_CSS_Octubre2026.xlsx",
                    "Liquidaciones_Colaboradores_2026.pdf",
                ],
            },
        ),
        EndpointIngestRequest(
            hostname="PC-FINANZAS-04",
            username="CORP\\rbatista",
            ip_address="192.168.10.48",
            os_version="Windows 11 Pro 23H2",
            shadow_ai_dns_hits=[
                {"domain": "deepseek.com", "count": 27, "category": "LLM Conversacional"},
                {"domain": "perplexity.ai", "count": 16, "category": "Buscador IA"},
                {"domain": "chatgpt.com", "count": 12, "category": "LLM Conversacional"},
            ],
            risky_extensions=[
                {
                    "extension_id": "maxaimeext123890",
                    "name": "MaxAI.me: Summarize & Rewrite Anywhere",
                    "browser": "Chrome",
                    "permissions": ["<all_urls>", "scripting"],
                    "has_all_urls": True,
                }
            ],
            box_audit={
                "installed": True,
                "sync_path": "C:\\Users\\rbatista\\Box\\Estados_Financieros",
                "total_synced_files": 412,
                "sensitive_files_count": 14,
                "dlp_enabled": False,
                "sample_files": ["Anexo_72_DGI_Proveedores_RUC.xlsx"],
            },
        ),
    ]

    for ep_req in sample_endpoints:
        ingest_endpoint_audit(ep_req, db)

    # Ejecutar un escaneo SMB simulado inicial para poblar hallazgos de Windows Server
    scanner = WindowsSmbScanner(server_ip="192.168.10.5")
    sim_data = scanner._generate_fallback_simulation("WIN-SRV-FS01", "Semilla inicial de auditoría", 0.0)
    smb_row = SmbScanResult(
        target_ip=sim_data["target_ip"],
        server_name=sim_data["server_name"],
        auth_mode=sim_data["auth_mode"],
        guest_access_allowed=sim_data["guest_access_allowed"],
        total_shares=sim_data["total_shares"],
        critical_shares_found=sim_data["critical_shares_found"],
        total_office_pdf_files=sim_data["total_office_pdf_files"],
        files_with_pii_count=sim_data["files_with_pii_count"],
        cedula_matches_count=sim_data["cedula_matches_count"],
        ruc_matches_count=sim_data["ruc_matches_count"],
        email_matches_count=sim_data["email_matches_count"],
        findings_detail=sim_data["findings_detail"],
        scan_duration_ms=42,
    )
    db.add(smb_row)
    db.commit()
