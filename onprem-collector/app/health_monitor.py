"""Local health monitor probing Collector, SQLite, AdGuard, Cloudflared Tunnel, Scanners, and Wazuh."""

from __future__ import annotations

import ctypes
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from .connectors.adguard_connector import AdGuardConnector
from .connectors.wazuh_connector import WazuhConnector
from .extractors import is_tesseract_available
from .models import DbScanResult, PendingSyncQueue, SmbScanResult
from .pii_bridge import get_pii_engine_status

COLLECTOR_VERSION = "2.0.0"

try:
    from .reports.report_generator import WEASYPRINT_AVAILABLE
except Exception:
    WEASYPRINT_AVAILABLE = False


def _get_system_metrics() -> Tuple[float, float]:
    """Return (cpu_pct, ram_mb) using stdlib/procfs on Linux or ctypes on Windows."""
    ram_mb = 0.0
    cpu_pct = 0.0

    # Linux /proc inspection
    proc_status = Path("/proc/self/status")
    if proc_status.exists():
        try:
            for line in proc_status.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("VmRSS:"):
                    kb = float(line.split()[1])
                    ram_mb = round(kb / 1024.0, 1)
                    break
        except Exception:
            pass

    if os.name == "nt":
        try:
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb
            ):
                ram_mb = round(counters.WorkingSetSize / (1024.0 * 1024.0), 1)
        except Exception:
            pass

    try:
        if hasattr(os, "getloadavg"):
            load1 = os.getloadavg()[0]
            cpus = os.cpu_count() or 1
            cpu_pct = round(min(100.0, max(0.0, (load1 / cpus) * 100.0)), 1)
    except (OSError, AttributeError):
        cpu_pct = 0.0

    return cpu_pct, ram_mb


def probe_sqlite_health(db: Session) -> Dict[str, Any]:
    """Check SQLite WAL database connectivity and query latency."""
    start = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"ok": True, "latency_ms": latency_ms, "error": None}
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"ok": False, "latency_ms": latency_ms, "error": str(exc)}


async def probe_cloudflared_tunnel(
    metrics_url: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """Probe the local cloudflared /ready metrics endpoint."""
    target_url = (
        metrics_url
        if metrics_url is not None
        else os.getenv("CLOUDFLARED_METRICS_URL", "http://cloudflared:2000/ready")
    ).strip()

    if not target_url or target_url.lower() == "disabled":
        return {
            "status": "OFFLINE",
            "latency_ms": 0.0,
            "url": target_url,
            "last_error": "CLOUDFLARED_METRICS_URL not configured",
        }

    start = time.perf_counter()
    owns_client = client is None
    http_client = client or httpx.AsyncClient(timeout=1.5)
    try:
        resp = await http_client.get(target_url)
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        if resp.status_code == 200:
            return {
                "status": "DEGRADED" if latency_ms >= 1500 else "ONLINE",
                "latency_ms": latency_ms,
                "url": target_url,
                "last_error": None,
            }
        return {
            "status": "DEGRADED",
            "latency_ms": latency_ms,
            "url": target_url,
            "last_error": f"cloudflared metrics returned HTTP {resp.status_code}",
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {
            "status": "OFFLINE",
            "latency_ms": latency_ms,
            "url": target_url,
            "last_error": f"cloudflared unreachable at {target_url}: {exc}",
        }
    finally:
        if owns_client:
            await http_client.aclose()


async def collect_health_snapshot(
    db: Session,
    tenant_id: Optional[str] = None,
    adguard_connector: Optional[AdGuardConnector] = None,
    wazuh_connector: Optional[WazuhConnector] = None,
    tunnel_metrics_url: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """Probe all collector subsystems and build Control Plane HeartbeatPayloads."""
    resolved_tenant = (tenant_id or os.getenv("TENANT_ID", "default-tenant")).strip()
    collector_id = os.getenv("COLLECTOR_ID", "collector-01").strip() or "collector-01"
    now_iso = datetime.now(timezone.utc).isoformat()

    cpu_pct, ram_mb = _get_system_metrics()
    sqlite_health = probe_sqlite_health(db)
    pii_status = get_pii_engine_status()
    ocr_available = is_tesseract_available()

    adguard = adguard_connector or AdGuardConnector()
    adguard_health = await adguard.probe_status(client=client)

    tunnel_health = await probe_cloudflared_tunnel(
        metrics_url=tunnel_metrics_url, client=client
    )

    wazuh = wazuh_connector or WazuhConnector()
    wazuh_health = await wazuh.probe(client=client)

    latest_smb = db.query(SmbScanResult).order_by(SmbScanResult.created_at.desc()).first()
    latest_db = db.query(DbScanResult).order_by(DbScanResult.created_at.desc()).first()
    pending_sync_count = (
        db.query(PendingSyncQueue).filter(PendingSyncQueue.status == "PENDING").count()
    )

    collector_status = "ONLINE" if sqlite_health["ok"] else "DEGRADED"
    collector_error = sqlite_health["error"]

    smb_status = "ONLINE"
    smb_error: Optional[str] = None
    smb_meta: Dict[str, Any] = {"has_scan": latest_smb is not None}
    if latest_smb is not None:
        smb_meta.update(
            {
                "last_scan_at": latest_smb.created_at.isoformat() if latest_smb.created_at else None,
                "target_ip": latest_smb.target_ip,
                "is_simulated": bool(latest_smb.is_simulated),
                "files_with_pii_count": latest_smb.files_with_pii_count,
                "retention_violations_count": latest_smb.retention_violations_count,
            }
        )
        if latest_smb.is_simulated:
            smb_status = "DEGRADED"
            smb_error = "Último escaneo SMB ejecutado en modo simulación"

    db_status = "ONLINE"
    db_meta: Dict[str, Any] = {"has_scan": latest_db is not None}
    if latest_db is not None:
        db_meta.update(
            {
                "last_scan_at": latest_db.created_at.isoformat() if latest_db.created_at else None,
                "db_type": latest_db.db_type,
                "target_label": latest_db.target_label,
                "findings_count": latest_db.findings_count,
                "retention_violations_count": latest_db.retention_violations_count,
            }
        )

    heartbeats: List[Dict[str, Any]] = [
        {
            "tenant_id": resolved_tenant,
            "component_layer": "ONPREM_COLLECTOR",
            "component_id": f"{resolved_tenant}-{collector_id}",
            "display_name": "On-Premise Collector Core",
            "status": collector_status,
            "latency_ms": sqlite_health["latency_ms"],
            "version": COLLECTOR_VERSION,
            "cpu_pct": cpu_pct,
            "ram_mb": ram_mb,
            "last_error": collector_error,
            "metadata": {
                "sqlite_ok": sqlite_health["ok"],
                "pending_sync_queue": pending_sync_count,
                "ocr_available": ocr_available,
                "weasyprint_available": WEASYPRINT_AVAILABLE,
                "pii_engine": pii_status,
            },
            "timestamp": now_iso,
        },
        {
            "tenant_id": resolved_tenant,
            "component_layer": "TUNNEL",
            "component_id": f"{resolved_tenant}-cf-tunnel-01",
            "display_name": "Cloudflare Zero Trust Tunnel",
            "status": tunnel_health["status"],
            "latency_ms": tunnel_health["latency_ms"],
            "version": COLLECTOR_VERSION,
            "last_error": tunnel_health["last_error"],
            "metadata": {"metrics_url": tunnel_health["url"]},
            "timestamp": now_iso,
        },
        {
            "tenant_id": resolved_tenant,
            "component_layer": "ADGUARD_DNS",
            "component_id": f"{resolved_tenant}-adguard-dns-01",
            "display_name": "AdGuard DNS Shadow-AI Sensor",
            "status": adguard_health["adguard_status"],
            "latency_ms": adguard_health["latency_ms"],
            "version": str(adguard_health.get("version") or "unknown"),
            "last_error": adguard_health["last_error"],
            "metadata": {
                "live_connected": adguard_health["adguard_live_connected"],
                "endpoint": adguard.base_url,
            },
            "timestamp": now_iso,
        },
        {
            "tenant_id": resolved_tenant,
            "component_layer": "SMB_CONNECTOR",
            "component_id": f"{resolved_tenant}-smb-connector-01",
            "display_name": "Windows File Server SMB Connector",
            "status": smb_status,
            "latency_ms": float(latest_smb.scan_duration_ms) if latest_smb else 0.0,
            "version": COLLECTOR_VERSION,
            "last_error": smb_error,
            "metadata": smb_meta,
            "timestamp": now_iso,
        },
        {
            "tenant_id": resolved_tenant,
            "component_layer": "DB_CONNECTOR",
            "component_id": f"{resolved_tenant}-db-connector-01",
            "display_name": "SQL Database Connector",
            "status": db_status,
            "latency_ms": float(latest_db.scan_duration_ms) if latest_db else 0.0,
            "version": COLLECTOR_VERSION,
            "last_error": None,
            "metadata": db_meta,
            "timestamp": now_iso,
        },
        {
            "tenant_id": resolved_tenant,
            "component_layer": "WAZUH_FIM",
            "component_id": f"{resolved_tenant}-wazuh-fim-01",
            "display_name": "Wazuh FIM Integrity Monitor",
            "status": wazuh_health["status"],
            "latency_ms": wazuh_health["latency_ms"],
            "version": COLLECTOR_VERSION,
            "last_error": wazuh_health["last_error"],
            "metadata": {
                "configured": wazuh_health["configured"],
                "agents_active": wazuh_health["agents_active"],
            },
            "timestamp": now_iso,
        },
    ]

    return {
        "ok": sqlite_health["ok"],
        "service": "vektor81-onprem-collector",
        "version": COLLECTOR_VERSION,
        "tenant_id": resolved_tenant,
        "timestamp": now_iso,
        "system": {
            "cpu_pct": cpu_pct,
            "ram_mb": ram_mb,
            "sqlite": sqlite_health,
            "ocr_available": ocr_available,
            "weasyprint_available": WEASYPRINT_AVAILABLE,
            "pii_engine": pii_status,
            "pending_sync_queue": pending_sync_count,
        },
        "subsystems": {
            "adguard": adguard_health,
            "tunnel": tunnel_health,
            "wazuh": wazuh_health,
            "smb_last_scan": smb_meta,
            "db_last_scan": db_meta,
        },
        "heartbeats": heartbeats,
    }
