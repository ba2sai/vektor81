"""
FastAPI entrypoint for Vektor81 v2 On-Premise Collector.
Hardened with mandatory Bearer auth, strict CORS, real extractors, SQL DB + SMB scanners,
live AdGuard/Wazuh/Tunnel health monitoring, and Control Plane store-and-forward sync.
"""

from __future__ import annotations

import hmac
import logging
import os
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from . import models
from .connectors.adguard_connector import AdGuardConnector, AI_DOMAINS_MAP, match_shadow_ai_domain
from .health_monitor import COLLECTOR_VERSION, collect_health_snapshot
from .models import (
    CollectorConfig,
    DbScanRequest,
    DbScanResult,
    DnsAuditSnapshot,
    EndpointAsset,
    EndpointIngestLog,
    EndpointIngestRequest,
    PendingSyncQueue,
    SmbScanRequest,
    SmbScanResult,
    SyncNowRequest,
)
from .reports.report_generator import (
    calculate_ley81_risk_score,
    generate_executive_pdf_bytes,
    generate_ficha_tecnica_json,
    render_executive_html,
)
from .scanners.db_scanner import DbScanner
from .scanners.smb_scanner import WindowsSmbScanner
from .sync_client import ControlPlaneSyncClient, sanitize_endpoint_payload_for_control_plane

logger = logging.getLogger("vektor81.onprem_collector")


def _parse_allowed_origins() -> List[str]:
    raw = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost",
    )
    origins = [item.strip() for item in raw.split(",") if item.strip() and item.strip() != "*"]
    return origins or ["http://localhost:5173", "http://localhost"]


def _get_tenant_and_profile(db: Session) -> tuple[str, str, bool]:
    cfg = db.query(CollectorConfig).order_by(CollectorConfig.id.asc()).first()
    if cfg:
        return (
            cfg.tenant_id,
            cfg.regulatory_profile,
            bool(cfg.dpo_antai_registered),
        )
    return (
        os.getenv("TENANT_ID", "default-tenant").strip() or "default-tenant",
        os.getenv("REGULATORY_PROFILE", "ANTAI_LEY81").strip().upper() or "ANTAI_LEY81",
        False,
    )


def require_bearer_token(authorization: Optional[str] = Header(default=None)) -> str:
    """Enforce mandatory Bearer authentication on all non-ping routes."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")

    token = authorization[len("Bearer ") :].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty Bearer token")

    primary_token = os.getenv("ONPREM_API_TOKEN", "").strip()
    if primary_token and hmac.compare_digest(token, primary_token):
        return token

    env_mode = os.getenv("VEKTOR81_ENV", "production").strip().lower()
    dev_token = os.getenv("ONPREM_DEV_API_TOKEN", "").strip()
    if env_mode == "development" and dev_token and hmac.compare_digest(token, dev_token):
        logger.warning("Authenticated using ONPREM_DEV_API_TOKEN in development mode")
        return token

    raise HTTPException(status_code=401, detail="Invalid Bearer token")


def get_db():
    db = models.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    models.init_db()
    yield


app = FastAPI(
    title="Vektor81 v2 — On-Premise Collector",
    description=(
        "Colector híbrido endurecido para auditoría de Shadow AI, PII Panameña (Ley 81 / DE 285), "
        "repositorios SMB/SQL y sincronización cifrada hacia Cloudflare Control Plane."
    ),
    version=COLLECTOR_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-Id"],
)


# =====================================================================
# HEALTH ENDPOINTS
# =====================================================================


@app.get("/api/v1/health/ping", tags=["Health"])
def health_ping() -> Dict[str, Any]:
    """Unauthenticated liveness probe."""
    return {
        "ok": True,
        "service": "vektor81-onprem-collector",
        "version": COLLECTOR_VERSION,
        "environment": os.getenv("VEKTOR81_ENV", "production"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/health", tags=["Health"])
async def get_health_status(
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Authenticated comprehensive subsystem health and heartbeat payload view."""
    tenant_id, _profile, _dpo = _get_tenant_and_profile(db)
    return await collect_health_snapshot(db=db, tenant_id=tenant_id)


@app.post("/api/v1/health/heartbeat", tags=["Health"])
async def ingest_component_heartbeat(
    payload: Dict[str, Any],
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Accept endpoint/component heartbeat and relay or queue for Control Plane."""
    default_tenant, _profile, _dpo = _get_tenant_and_profile(db)
    tenant_id = str(payload.get("tenant_id") or default_tenant).strip()
    component_layer = str(payload.get("component_layer") or "ENDPOINT_AGENT").strip()
    component_id = str(payload.get("component_id") or "").strip()

    if not component_id:
        raise HTTPException(status_code=400, detail="Missing component_id in heartbeat payload")

    if component_layer == "ENDPOINT_AGENT":
        hostname_norm = component_id.upper()
        asset = db.query(EndpointAsset).filter(EndpointAsset.hostname == hostname_norm).first()
        if asset:
            asset.last_seen = datetime.now(timezone.utc)
            db.commit()

    normalized_hb = {
        "tenant_id": tenant_id,
        "component_layer": component_layer,
        "component_id": component_id,
        "display_name": str(payload.get("display_name") or component_id),
        "status": str(payload.get("status") or "ONLINE"),
        "version": str(payload.get("version") or "2.0.0"),
        "metadata": payload.get("metadata") or {},
        "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
    }

    sync_client = ControlPlaneSyncClient(tenant_id=tenant_id)
    sync_res = None
    if sync_client.is_configured:
        sync_res = await sync_client.send_or_queue(
            db, "/api/v2/health/heartbeat", normalized_hb, tenant_id=tenant_id
        )

    return {"ok": True, "component_id": component_id, "control_plane_sync": sync_res}


# =====================================================================
# MODULE 1: ENDPOINT INGEST (POST /api/v1/ingest)
# =====================================================================


def _ingest_endpoint_record(payload: EndpointIngestRequest, db: Session) -> Dict[str, Any]:
    default_tenant, _profile, _dpo = _get_tenant_and_profile(db)
    tenant_id = (payload.tenant_id or default_tenant).strip()
    hostname_norm = payload.hostname.strip().upper()
    total_dns_hits = sum(item.count for item in payload.shadow_ai_dns_hits)
    all_urls_exts = [
        ext
        for ext in payload.risky_extensions
        if ext.has_all_urls or "<all_urls>" in ext.permissions
    ]
    box_exposed = (
        payload.box_audit.sensitive_files_count if not payload.box_audit.dlp_enabled else 0
    )
    onedrive_exposed = (
        payload.onedrive_audit.sensitive_files_count
        if payload.onedrive_audit and not payload.onedrive_audit.dlp_enabled
        else 0
    )

    ep_risk = min(
        100.0,
        round(
            (total_dns_hits * 2.5)
            + (len(all_urls_exts) * 18.0)
            + (box_exposed * 1.5)
            + (onedrive_exposed * 1.2),
            1,
        ),
    )

    asset = db.query(EndpointAsset).filter(EndpointAsset.hostname == hostname_norm).first()
    if not asset:
        asset = EndpointAsset(
            tenant_id=tenant_id,
            hostname=hostname_norm,
            username=payload.username,
            ip_address=payload.ip_address,
            os_version=payload.os_version or "Windows 11 Pro",
            agent_version=payload.agent_version or "2.0.0",
        )
        db.add(asset)
        db.flush()
    else:
        asset.tenant_id = tenant_id
        asset.username = payload.username
        if payload.ip_address:
            asset.ip_address = payload.ip_address
        if payload.os_version:
            asset.os_version = payload.os_version
        if payload.agent_version:
            asset.agent_version = payload.agent_version
        asset.last_seen = datetime.now(timezone.utc)

    asset.dns_hits_count = total_dns_hits
    asset.risky_extensions_count = len(all_urls_exts)
    asset.box_exposed_files = payload.box_audit.sensitive_files_count
    asset.box_dlp_active = payload.box_audit.dlp_enabled
    asset.onedrive_exposed_files = (
        payload.onedrive_audit.sensitive_files_count if payload.onedrive_audit else 0
    )
    asset.onedrive_dlp_active = (
        payload.onedrive_audit.dlp_enabled if payload.onedrive_audit else False
    )
    asset.endpoint_risk_score = ep_risk

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
        tenant_id=tenant_id,
        hostname=hostname_norm,
        username=payload.username,
        shadow_ai_dns_hits=enriched_dns_hits,
        risky_extensions=[ext.model_dump() for ext in payload.risky_extensions],
        box_audit=payload.box_audit.model_dump(),
        onedrive_audit=payload.onedrive_audit.model_dump() if payload.onedrive_audit else None,
    )
    db.add(ingest_log)
    db.commit()
    db.refresh(asset)

    return {
        "status": "ingested",
        "tenant_id": tenant_id,
        "asset_id": asset.id,
        "hostname": asset.hostname,
        "endpoint_risk_score": asset.endpoint_risk_score,
        "summary": {
            "dns_hits_count": asset.dns_hits_count,
            "risky_extensions_count": asset.risky_extensions_count,
            "box_exposed_files": asset.box_exposed_files,
            "box_dlp_active": asset.box_dlp_active,
        },
        "_enriched_payload": {
            **payload.model_dump(),
            "shadow_ai_dns_hits": enriched_dns_hits,
        },
    }


@app.post("/api/v1/ingest", tags=["Module 1: Endpoint Ingest"])
async def ingest_endpoint_audit(
    payload: EndpointIngestRequest,
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Ingest Windows endpoint PowerShell audit payload and queue/sync anonymized telemetry."""
    result = _ingest_endpoint_record(payload, db)
    enriched_raw = result.pop("_enriched_payload")

    sync_client = ControlPlaneSyncClient(tenant_id=result["tenant_id"])
    if sync_client.is_configured:
        cp_payload = sanitize_endpoint_payload_for_control_plane(
            result["tenant_id"], enriched_raw
        )
        sync_res = await sync_client.send_or_queue(
            db, "/api/v2/ingest/endpoint", cp_payload, tenant_id=result["tenant_id"]
        )
        if payload.heartbeat:
            hb_payload = {**payload.heartbeat, "tenant_id": result["tenant_id"]}
            await sync_client.send_or_queue(
                db, "/api/v2/health/heartbeat", hb_payload, tenant_id=result["tenant_id"]
            )
        result["control_plane_sync"] = sync_res
    return result


# =====================================================================
# MODULE 2: WINDOWS SERVER SMB SCANNER (POST /api/v1/scan-smb)
# =====================================================================


@app.post("/api/v1/scan-smb", tags=["Module 2: SMB Scanner"])
async def scan_windows_smb_server(
    req: SmbScanRequest,
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Audit SMB shares using real document/OCR extractors and panama-pii-py."""
    default_tenant, default_profile, _dpo = _get_tenant_and_profile(db)
    tenant_id = (req.tenant_id or default_tenant).strip()
    reg_profile = (req.regulatory_profile or default_profile).strip().upper()

    scanner = WindowsSmbScanner(
        server_ip=req.server_ip,
        username=req.username or "",
        password=req.password or "",
        domain=req.domain or "WORKGROUP",
        port=req.port,
        max_depth=req.max_depth,
        max_file_mb=req.max_file_mb,
        regulatory_profile=reg_profile,
        tenant_id=tenant_id,
    )

    try:
        result_data = scanner.run_scan(simulate_if_unreachable=req.simulate_if_unreachable)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    smb_record = SmbScanResult(
        scan_id=result_data["scan_id"],
        tenant_id=tenant_id,
        regulatory_profile=reg_profile,
        target_ip=result_data["target_ip"],
        server_name=result_data["server_name"],
        auth_mode=result_data["auth_mode"],
        guest_access_allowed=result_data["guest_access_allowed"],
        is_simulated=bool(result_data["is_simulated"]),
        total_shares=result_data["total_shares"],
        critical_shares_found=result_data["critical_shares_found"],
        total_office_pdf_files=result_data["total_office_pdf_files"],
        files_with_pii_count=result_data["files_with_pii_count"],
        cedula_matches_count=result_data["cedula_matches_count"],
        ruc_matches_count=result_data["ruc_matches_count"],
        email_matches_count=result_data["email_matches_count"],
        sensitive_findings_count=result_data["sensitive_findings_count"],
        retention_violations_count=result_data["retention_violations_count"],
        findings_detail=result_data["findings_detail"],
        findings_v2=result_data["findings_v2"],
        scan_duration_ms=result_data["scan_duration_ms"],
    )
    db.add(smb_record)
    db.commit()
    db.refresh(smb_record)

    sync_client = ControlPlaneSyncClient(tenant_id=tenant_id)
    sync_status = None
    if sync_client.is_configured:
        sync_status = await sync_client.send_or_queue(
            db,
            "/api/v2/ingest/findings",
            result_data["finding_batch_payload"],
            tenant_id=tenant_id,
        )

    return {
        "db_record_id": smb_record.id,
        "created_at": smb_record.created_at.isoformat(),
        "control_plane_sync": sync_status,
        **result_data,
    }


# =====================================================================
# MODULE 2B: RELATIONAL DB SCANNER (POST /api/v1/scan-db)
# =====================================================================


@app.post("/api/v1/scan-db", tags=["Module 2B: SQL DB Scanner"])
async def scan_relational_database(
    req: DbScanRequest,
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Inspect SQLite/PostgreSQL/MySQL/MSSQL/Oracle tables locally and emit masked PII findings."""
    default_tenant, default_profile, _dpo = _get_tenant_and_profile(db)
    tenant_id = (req.tenant_id or default_tenant).strip()
    reg_profile = (req.regulatory_profile or default_profile).strip().upper()

    scanner = DbScanner(
        db_type=req.db_type,
        sqlite_path=req.sqlite_path,
        host=req.host,
        port=req.port,
        database=req.database,
        username=req.username,
        password=req.password,
        dsn=req.dsn,
        repository_name=req.repository_name,
        regulatory_profile=reg_profile,
        tenant_id=tenant_id,
        sample_limit=req.sample_limit,
    )

    try:
        result_data = scanner.run_scan(tables=req.tables)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    db_record = DbScanResult(
        scan_id=result_data["scan_id"],
        tenant_id=tenant_id,
        regulatory_profile=reg_profile,
        db_type=result_data["db_type"],
        target_label=result_data["target_label"],
        tables_scanned=result_data["tables_scanned"],
        rows_sampled=result_data["rows_sampled"],
        tables_with_pii_count=result_data["tables_with_pii_count"],
        findings_count=result_data["findings_count"],
        sensitive_findings_count=result_data["sensitive_findings_count"],
        retention_violations_count=result_data["retention_violations_count"],
        findings_detail=result_data["findings"],
        scan_duration_ms=result_data["scan_duration_ms"],
        is_simulated=False,
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    sync_client = ControlPlaneSyncClient(tenant_id=tenant_id)
    sync_status = None
    if sync_client.is_configured:
        sync_status = await sync_client.send_or_queue(
            db,
            "/api/v2/ingest/findings",
            result_data["finding_batch_payload"],
            tenant_id=tenant_id,
        )

    return {
        "db_record_id": db_record.id,
        "created_at": db_record.created_at.isoformat(),
        "control_plane_sync": sync_status,
        **result_data,
    }


# =====================================================================
# MODULE 3: ADGUARD DNS SHADOW AI CONNECTOR (GET /api/v1/dns-stats)
# =====================================================================


@app.get("/api/v1/dns-stats", tags=["Module 3: AdGuard DNS"])
async def get_adguard_dns_stats(
    limit: int = Query(default=500, ge=50, le=2000),
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Query live AdGuard Home /control/querylog + combine endpoint DNS telemetry honestly."""
    tenant_id, _profile, _dpo = _get_tenant_and_profile(db)
    connector = AdGuardConnector()
    live_res = await connector.fetch_querylog_stats(tenant_id=tenant_id, limit=limit)

    by_client_ip: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"total_hits": 0, "domains": defaultdict(int)}
    )
    by_category: Dict[str, int] = defaultdict(int)
    by_domain: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "category": ""}
    )

    for c in live_res["by_client_ip"]:
        by_client_ip[c["client"]]["total_hits"] += c["total_hits"]
        for d in c["domains"]:
            by_client_ip[c["client"]]["domains"][d["domain"]] += d["count"]

    for cat in live_res["by_category"]:
        by_category[cat["category"]] += cat["count"]

    for dom in live_res["top_domains"]:
        by_domain[dom["domain"]]["count"] += dom["count"]
        by_domain[dom["domain"]]["category"] = dom["category"]

    total_inspected = int(live_res["total_queries_inspected"])

    # Complement with latest endpoint DNS cache reports stored in SQLite
    latest_logs = (
        db.query(EndpointIngestLog).order_by(EndpointIngestLog.created_at.desc()).limit(50).all()
    )
    seen_hosts = set()
    for log in latest_logs:
        if log.hostname in seen_hosts:
            continue
        seen_hosts.add(log.hostname)
        asset = db.query(EndpointAsset).filter(EndpointAsset.id == log.asset_id).first()
        client_key = f"{asset.ip_address or 'LAN'} ({log.hostname})" if asset else log.hostname

        for hit in log.shadow_ai_dns_hits or []:
            dom = str(hit.get("domain", "")).lower()
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

    formatted_clients = [
        {
            "client": client,
            "total_hits": info["total_hits"],
            "domains": [
                {"domain": d, "count": c}
                for d, c in sorted(info["domains"].items(), key=lambda x: -x[1])
            ],
        }
        for client, info in sorted(by_client_ip.items(), key=lambda x: -x[1]["total_hits"])
    ]
    formatted_domains = [
        {"domain": dom, "count": info["count"], "category": info["category"]}
        for dom, info in sorted(by_domain.items(), key=lambda x: -x[1]["count"])
    ]
    formatted_categories = [
        {"category": cat, "count": cnt}
        for cat, cnt in sorted(by_category.items(), key=lambda x: -x[1])
    ]
    total_shadow_hits = sum(item["count"] for item in formatted_domains)

    snapshot = DnsAuditSnapshot(
        tenant_id=tenant_id,
        adguard_status=live_res["adguard_status"],
        latency_ms=live_res["latency_ms"],
        last_error=live_res["last_error"],
        total_queries_inspected=total_inspected,
        shadow_ai_hits_total=total_shadow_hits,
        by_client_ip={c["client"]: c for c in formatted_clients},
        by_category=dict(by_category),
        by_domain={d["domain"]: d["count"] for d in formatted_domains},
    )
    db.add(snapshot)
    db.commit()

    return {
        "adguard_status": live_res["adguard_status"],
        "adguard_live_connected": live_res["adguard_live_connected"],
        "latency_ms": live_res["latency_ms"],
        "last_error": live_res["last_error"],
        "adguard_endpoint": live_res["adguard_endpoint"],
        "dictionary_domains_loaded": len(AI_DOMAINS_MAP),
        "total_queries_inspected": total_inspected,
        "shadow_ai_hits_total": total_shadow_hits,
        "by_client_ip": formatted_clients,
        "by_category": formatted_categories,
        "top_domains": formatted_domains[:15],
        "shadow_ai_batch": live_res["shadow_ai_batch"],
    }


# =====================================================================
# MODULE 4: SYNC TO CONTROL PLANE (POST /api/v1/sync-now)
# =====================================================================


@app.post("/api/v1/sync-now", tags=["Module 4: Control Plane Sync"])
async def sync_now(
    req: Optional[SyncNowRequest] = None,
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Flush offline queue and push fresh collector heartbeats (+ optional AdGuard Shadow AI)."""
    default_tenant, _profile, _dpo = _get_tenant_and_profile(db)
    tenant_id = ((req.tenant_id if req else None) or default_tenant).strip()
    include_heartbeats = req.include_heartbeats if req else True
    include_dns = req.include_dns if req else False

    extra_batches = []
    if include_dns:
        dns_res = await AdGuardConnector().fetch_querylog_stats(tenant_id=tenant_id, limit=500)
        if dns_res["shadow_ai_batch"]["events"]:
            extra_batches.append(("/api/v2/ingest/shadow-ai", dns_res["shadow_ai_batch"]))

    sync_client = ControlPlaneSyncClient(tenant_id=tenant_id)
    return await sync_client.sync_once(
        db=db,
        include_heartbeats=include_heartbeats,
        extra_batches=extra_batches,
    )


# =====================================================================
# MODULE 5: DASHBOARD, EXECUTIVE REPORT & FICHA TÉCNICA
# =====================================================================


def _build_audit_context(db: Session) -> Dict[str, Any]:
    tenant_id, reg_profile, dpo_registered = _get_tenant_and_profile(db)
    endpoints = db.query(EndpointAsset).order_by(EndpointAsset.endpoint_risk_score.desc()).all()
    latest_smb = db.query(SmbScanResult).order_by(SmbScanResult.created_at.desc()).first()
    latest_db = db.query(DbScanResult).order_by(DbScanResult.created_at.desc()).first()
    latest_dns = db.query(DnsAuditSnapshot).order_by(DnsAuditSnapshot.created_at.desc()).first()
    pending_sync_count = (
        db.query(PendingSyncQueue).filter(PendingSyncQueue.status == "PENDING").count()
    )

    domain_counter: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "category": "LLM Conversacional"}
    )
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
            dom = str(hit.get("domain", "")).lower()
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

    if latest_dns and latest_dns.by_domain:
        for dom, cnt in latest_dns.by_domain.items():
            matched = match_shadow_ai_domain(dom)
            if dom not in domain_counter:
                domain_counter[dom]["count"] = int(cnt)
                domain_counter[dom]["category"] = matched[1] if matched else "LLM Conversacional"

    top_ai_domains = [
        {"domain": dom, "count": info["count"], "category": info["category"]}
        for dom, info in sorted(domain_counter.items(), key=lambda x: -x[1]["count"])
    ]

    total_shadow_ai_hits = sum(d["count"] for d in top_ai_domains)
    adguard_live_hits = latest_dns.shadow_ai_hits_total if latest_dns else 0
    smb_pii_files = latest_smb.files_with_pii_count if latest_smb else 0
    smb_guest_allowed = latest_smb.guest_access_allowed if latest_smb else False
    smb_ret_violations = latest_smb.retention_violations_count if latest_smb else 0

    db_findings_count = latest_db.findings_count if latest_db else 0
    db_sensitive_count = latest_db.sensitive_findings_count if latest_db else 0
    db_ret_violations = latest_db.retention_violations_count if latest_db else 0
    retention_violations_total = smb_ret_violations + db_ret_violations

    risk_evaluation = calculate_ley81_risk_score(
        total_shadow_ai_hits=total_shadow_ai_hits,
        unique_ai_domains_count=len(top_ai_domains),
        smb_pii_files_count=smb_pii_files,
        smb_guest_allowed=smb_guest_allowed,
        box_unprotected_files_count=box_unprotected_files_total,
        all_urls_extensions_count=all_urls_extensions_total,
        audited_endpoints_count=len(endpoints),
        adguard_live_hits=adguard_live_hits,
        db_findings_count=db_findings_count,
        db_sensitive_findings_count=db_sensitive_count,
        retention_violations_count=retention_violations_total,
        regulatory_profile=reg_profile,
        dpo_registered=dpo_registered,
    )

    smb_dict = None
    if latest_smb:
        smb_dict = {
            "id": latest_smb.id,
            "scan_id": latest_smb.scan_id,
            "target_ip": latest_smb.target_ip,
            "server_name": latest_smb.server_name,
            "auth_mode": latest_smb.auth_mode,
            "guest_access_allowed": latest_smb.guest_access_allowed,
            "is_simulated": latest_smb.is_simulated,
            "total_shares": latest_smb.total_shares,
            "critical_shares_found": latest_smb.critical_shares_found,
            "total_office_pdf_files": latest_smb.total_office_pdf_files,
            "files_with_pii_count": latest_smb.files_with_pii_count,
            "cedula_matches_count": latest_smb.cedula_matches_count,
            "ruc_matches_count": latest_smb.ruc_matches_count,
            "email_matches_count": latest_smb.email_matches_count,
            "retention_violations_count": latest_smb.retention_violations_count,
            "findings_detail": latest_smb.findings_detail,
            "created_at": latest_smb.created_at.isoformat(),
        }

    db_dict = None
    if latest_db:
        db_dict = {
            "id": latest_db.id,
            "scan_id": latest_db.scan_id,
            "db_type": latest_db.db_type,
            "target_label": latest_db.target_label,
            "tables_scanned": latest_db.tables_scanned,
            "rows_sampled": latest_db.rows_sampled,
            "tables_with_pii_count": latest_db.tables_with_pii_count,
            "findings_count": latest_db.findings_count,
            "sensitive_findings_count": latest_db.sensitive_findings_count,
            "retention_violations_count": latest_db.retention_violations_count,
            "findings_detail": latest_db.findings_detail,
            "created_at": latest_db.created_at.isoformat(),
        }

    return {
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "kpis": {
            "audited_endpoints": len(endpoints),
            "shadow_ai_events": total_shadow_ai_hits,
            "exposed_files_smb_box": smb_pii_files + box_unprotected_files_total,
            "db_findings_count": db_findings_count,
            "retention_violations_total": retention_violations_total,
            "global_risk_score": risk_evaluation["total_score"],
        },
        "risk": risk_evaluation,
        "endpoints": detailed_endpoints,
        "top_ai_domains": top_ai_domains[:12],
        "latest_smb": smb_dict,
        "latest_db": db_dict,
        "adguard_status": {
            "adguard_status": latest_dns.adguard_status if latest_dns else "UNKNOWN",
            "adguard_live_connected": bool(
                latest_dns and latest_dns.adguard_status in ("ONLINE", "DEGRADED")
            ),
            "last_error": latest_dns.last_error if latest_dns else None,
        },
        "pending_sync_count": pending_sync_count,
    }


@app.get("/api/v1/dashboard", tags=["Module 5: Dashboard & Reports"])
def get_dashboard_overview(
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Consolidated KPIs, Shadow AI analytics, SMB/DB findings, and Ley 81 score."""
    return _build_audit_context(db)


@app.get("/api/v1/report/pdf", tags=["Module 5: Dashboard & Reports"])
def generate_ley81_pdf_report(
    format: str = Query(default="pdf", pattern="^(pdf|html)$"),
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
):
    """Compile Executive Report as WeasyPrint PDF (or clean HTML fallback when GTK missing)."""
    context = _build_audit_context(db)
    if format == "html":
        return HTMLResponse(content=render_executive_html(context))

    payload_bytes, media_type, is_fallback = generate_executive_pdf_bytes(context)
    if is_fallback:
        return HTMLResponse(
            content=payload_bytes.decode("utf-8"),
            headers={"X-WeasyPrint-Fallback": "html-weasyprint-unavailable"},
        )

    filename = f"Informe_Ejecutivo_Ley81_Panama_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return Response(
        content=payload_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/v1/ficha-tecnica", tags=["Module 5: Dashboard & Reports"])
def get_ficha_tecnica(
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Generate deterministic Panama Ley 81 Ficha Técnica JSON with SHA-256 hash."""
    context = _build_audit_context(db)
    return generate_ficha_tecnica_json(context)


@app.get("/api/v1/agent/powershell", tags=["Module 1: Endpoint Ingest"])
def download_powershell_collector(
    _token: str = Depends(require_bearer_token),
) -> Response:
    """Serve Vektor81-EndpointCollector.ps1 for endpoint deployment."""
    candidates = [
        Path("/app/agents/Vektor81-EndpointCollector.ps1"),
        Path(__file__).resolve().parents[2] / "agents" / "Vektor81-EndpointCollector.ps1",
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
    raise HTTPException(status_code=404, detail="PowerShell collector script not found.")


# =====================================================================
# EXPLICIT DEMO SEEDING (GATED BY ENABLE_DEMO_TOOLS=true)
# =====================================================================


@app.post("/api/v1/admin/seed-demo", tags=["Admin"])
def seed_demo_data(
    _token: str = Depends(require_bearer_token),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Explicit demo seed endpoint; strictly gated by ENABLE_DEMO_TOOLS=true."""
    if os.getenv("ENABLE_DEMO_TOOLS", "false").strip().lower() != "true":
        raise HTTPException(
            status_code=403,
            detail="Demo seeding is disabled (set ENABLE_DEMO_TOOLS=true to enable).",
        )

    tenant_id, reg_profile, _dpo = _get_tenant_and_profile(db)
    sample_endpoints = [
        EndpointIngestRequest(
            tenant_id=tenant_id,
            hostname="PC-LEGAL-01",
            username="CORP\\cmedina",
            ip_address="192.168.10.21",
            os_version="Windows 11 Pro 24H2",
            shadow_ai_dns_hits=[
                {"domain": "chatgpt.com", "count": 24, "category": "LLM Conversacional"},
                {"domain": "ilovepdf.com", "count": 14, "category": "Procesamiento PDF / Docs"},
            ],
            risky_extensions=[
                {
                    "extension_id": "harpaaiext001928192",
                    "name": "HARPA AI Automation Agent",
                    "browser": "Edge",
                    "permissions": ["<all_urls>", "activeTab"],
                    "has_all_urls": True,
                }
            ],
            box_audit={
                "provider": "BoxDrive",
                "installed": True,
                "sync_path": "C:\\Users\\cmedina\\Box\\Legal",
                "total_synced_files": 220,
                "sensitive_files_count": 14,
                "dlp_enabled": False,
                "sample_files_masked": ["Contrato_***_2026.docx"],
            },
        ),
        EndpointIngestRequest(
            tenant_id=tenant_id,
            hostname="PC-PLANILLA-02",
            username="CORP\\lcastillo",
            ip_address="192.168.10.34",
            os_version="Windows 11 Pro 24H2",
            shadow_ai_dns_hits=[
                {"domain": "claude.ai", "count": 18, "category": "LLM Conversacional"},
                {"domain": "deepseek.com", "count": 9, "category": "LLM Conversacional"},
            ],
            risky_extensions=[],
            box_audit={
                "provider": "BoxDrive",
                "installed": True,
                "sync_path": "C:\\Users\\lcastillo\\Box\\Planilla",
                "total_synced_files": 110,
                "sensitive_files_count": 9,
                "dlp_enabled": False,
                "sample_files_masked": ["Planilla_SIPE_****.xlsx"],
            },
        ),
    ]

    for ep in sample_endpoints:
        _ingest_endpoint_record(ep, db)

    scanner = WindowsSmbScanner(
        server_ip="192.168.10.5",
        regulatory_profile=reg_profile,
        tenant_id=tenant_id,
    )
    sim_data = scanner._generate_fallback_simulation("WIN-SRV-FS01", "Explicit demo seed", 0.0)
    smb_row = SmbScanResult(
        scan_id=sim_data["scan_id"],
        tenant_id=tenant_id,
        regulatory_profile=reg_profile,
        target_ip=sim_data["target_ip"],
        server_name=sim_data["server_name"],
        auth_mode=sim_data["auth_mode"],
        guest_access_allowed=sim_data["guest_access_allowed"],
        is_simulated=True,
        total_shares=sim_data["total_shares"],
        critical_shares_found=sim_data["critical_shares_found"],
        total_office_pdf_files=sim_data["total_office_pdf_files"],
        files_with_pii_count=sim_data["files_with_pii_count"],
        cedula_matches_count=sim_data["cedula_matches_count"],
        ruc_matches_count=sim_data["ruc_matches_count"],
        email_matches_count=sim_data["email_matches_count"],
        sensitive_findings_count=sim_data["sensitive_findings_count"],
        retention_violations_count=sim_data["retention_violations_count"],
        findings_detail=sim_data["findings_detail"],
        findings_v2=sim_data["findings_v2"],
        scan_duration_ms=15,
    )
    db.add(smb_row)
    db.commit()

    return {
        "ok": True,
        "endpoints_seeded": len(sample_endpoints),
        "smb_demo_scan_id": sim_data["scan_id"],
        "is_simulated": True,
    }
