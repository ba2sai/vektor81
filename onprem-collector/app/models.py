"""SQLAlchemy ORM (SQLite WAL) models and Pydantic schemas for Vektor81 On-Premise Collector."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/vektor81_collector.db")


def _ensure_sqlite_dir(db_url: str) -> None:
    if not db_url.startswith("sqlite:///"):
        return
    raw_path = db_url[len("sqlite:///") :]
    if raw_path == ":memory:" or not raw_path:
        return
    parent = Path(raw_path).parent
    if str(parent) and str(parent) != ".":
        parent.mkdir(parents=True, exist_ok=True)
    elif raw_path.startswith("./"):
        Path("./data").mkdir(parents=True, exist_ok=True)


def create_configured_engine(db_url: str):
    """Create a SQLAlchemy engine with SQLite WAL concurrency pragmas when applicable."""
    _ensure_sqlite_dir(db_url)
    eng = create_engine(
        db_url,
        connect_args={"check_same_thread": False, "timeout": 15} if db_url.startswith("sqlite") else {},
    )
    if db_url.startswith("sqlite"):

        @event.listens_for(eng, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA busy_timeout=15000;")
            cursor.execute("PRAGMA cache_size=-64000;")
            cursor.close()

    return eng


engine = create_configured_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def reconfigure_database(db_url: str) -> None:
    """Rebind global engine/SessionLocal (useful for isolated tests)."""
    global DATABASE_URL, engine, SessionLocal
    DATABASE_URL = db_url
    engine = create_configured_engine(db_url)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)


# =====================================================================
# SQLAlchemy ORM Models
# =====================================================================


class EndpointAsset(Base):
    """Inventory of audited Windows workstations."""

    __tablename__ = "endpoint_assets"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), index=True, nullable=False, default="default-tenant")
    hostname = Column(String(128), unique=True, index=True, nullable=False)
    username = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=True)
    os_version = Column(String(128), default="Windows 11 Pro")
    agent_version = Column(String(32), default="2.0.0")
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow)

    dns_hits_count = Column(Integer, default=0)
    risky_extensions_count = Column(Integer, default=0)
    box_exposed_files = Column(Integer, default=0)
    box_dlp_active = Column(Boolean, default=False)
    onedrive_exposed_files = Column(Integer, default=0)
    onedrive_dlp_active = Column(Boolean, default=False)
    endpoint_risk_score = Column(Float, default=0.0)

    ingest_logs = relationship(
        "EndpointIngestLog",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="desc(EndpointIngestLog.created_at)",
    )


class EndpointIngestLog(Base):
    """Immutable log of endpoint telemetry ingests."""

    __tablename__ = "endpoint_ingest_logs"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("endpoint_assets.id"), nullable=False)
    tenant_id = Column(String(64), index=True, nullable=False, default="default-tenant")
    hostname = Column(String(128), index=True, nullable=False)
    username = Column(String(128), nullable=False)
    shadow_ai_dns_hits = Column(JSON, default=list)
    risky_extensions = Column(JSON, default=list)
    box_audit = Column(JSON, default=dict)
    onedrive_audit = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)

    asset = relationship("EndpointAsset", back_populates="ingest_logs")


class SmbScanResult(Base):
    """Results of Windows File Server (SMB/CIFS) PII & retention scans."""

    __tablename__ = "smb_scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), index=True, nullable=True)
    tenant_id = Column(String(64), index=True, nullable=False, default="default-tenant")
    regulatory_profile = Column(String(32), default="ANTAI_LEY81")
    target_ip = Column(String(64), index=True, nullable=False)
    server_name = Column(String(128), nullable=True)
    auth_mode = Column(String(64), default="Guest/Anonymous")
    guest_access_allowed = Column(Boolean, default=False)
    is_simulated = Column(Boolean, default=False, nullable=False)
    total_shares = Column(Integer, default=0)
    critical_shares_found = Column(JSON, default=list)
    total_office_pdf_files = Column(Integer, default=0)
    files_with_pii_count = Column(Integer, default=0)
    cedula_matches_count = Column(Integer, default=0)
    ruc_matches_count = Column(Integer, default=0)
    email_matches_count = Column(Integer, default=0)
    sensitive_findings_count = Column(Integer, default=0)
    retention_violations_count = Column(Integer, default=0, nullable=False)
    findings_detail = Column(JSON, default=list)
    findings_v2 = Column(JSON, default=list)
    scan_duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow, index=True)


class DbScanResult(Base):
    """Results of relational database PII & retention scans."""

    __tablename__ = "db_scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), index=True, nullable=False)
    tenant_id = Column(String(64), index=True, nullable=False, default="default-tenant")
    regulatory_profile = Column(String(32), default="ANTAI_LEY81")
    db_type = Column(String(32), nullable=False)
    target_label = Column(String(256), nullable=False)
    tables_scanned = Column(Integer, default=0)
    rows_sampled = Column(Integer, default=0)
    tables_with_pii_count = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    sensitive_findings_count = Column(Integer, default=0)
    retention_violations_count = Column(Integer, default=0, nullable=False)
    findings_detail = Column(JSON, default=list)
    scan_duration_ms = Column(Integer, default=0)
    is_simulated = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, index=True)


class DnsAuditSnapshot(Base):
    """AdGuard Home DNS telemetry & Shadow AI inspection snapshots."""

    __tablename__ = "dns_audit_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), index=True, nullable=False, default="default-tenant")
    adguard_status = Column(String(16), default="OFFLINE")
    latency_ms = Column(Float, nullable=True)
    last_error = Column(Text, nullable=True)
    total_queries_inspected = Column(Integer, default=0)
    shadow_ai_hits_total = Column(Integer, default=0)
    by_client_ip = Column(JSON, default=dict)
    by_category = Column(JSON, default=dict)
    by_domain = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow, index=True)


class PendingSyncQueue(Base):
    """Offline store-and-forward queue for anonymized batches awaiting Control Plane sync."""

    __tablename__ = "pending_sync_queue"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), index=True, nullable=False)
    endpoint_path = Column(String(128), nullable=False)
    payload_json = Column(JSON, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    last_error = Column(Text, nullable=True)
    status = Column(String(16), default="PENDING", index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, index=True)
    next_retry_at = Column(DateTime, nullable=True)
    sent_at = Column(DateTime, nullable=True)


class CollectorConfig(Base):
    """Persistent collector tenant & regulatory profile configuration."""

    __tablename__ = "collector_config"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), unique=True, index=True, nullable=False)
    collector_id = Column(String(128), nullable=False, default="collector-01")
    display_name = Column(String(200), nullable=False, default="Vektor81 On-Premise Collector")
    regulatory_profile = Column(String(32), nullable=False, default="ANTAI_LEY81")
    dpo_name = Column(String(200), nullable=True)
    dpo_email = Column(String(200), nullable=True)
    dpo_antai_registered = Column(Boolean, default=False)
    control_plane_url = Column(String(256), nullable=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


def init_db(target_engine=None) -> None:
    Base.metadata.create_all(bind=target_engine or engine)


# =====================================================================
# Pydantic Request / Response Schemas
# =====================================================================


class ShadowAiDnsHitItem(BaseModel):
    domain: str = Field(..., examples=["chatgpt.com"])
    count: int = Field(default=1, ge=0)
    category: Optional[str] = Field(default="LLM Conversacional")
    last_timestamp: Optional[str] = None


class RiskyExtensionItem(BaseModel):
    extension_id: str = Field(..., examples=["efaidnbmnnnibpcajpcglclefindmkaj"])
    name: str = Field(..., examples=["Free AI PDF Summarizer & Chat"])
    browser: str = Field(default="Chrome", examples=["Chrome", "Edge"])
    version: Optional[str] = "1.0.0"
    permissions: List[str] = Field(default_factory=list)
    has_all_urls: bool = Field(default=True)


class CloudSyncAuditPayload(BaseModel):
    provider: str = Field(default="BoxDrive")
    installed: bool = Field(default=False)
    sync_path: Optional[str] = Field(default=None)
    total_synced_files: int = Field(default=0, ge=0)
    sensitive_files_count: int = Field(default=0, ge=0)
    dlp_enabled: bool = Field(default=False)
    sample_files: List[str] = Field(default_factory=list)
    sample_files_masked: List[str] = Field(default_factory=list)


class EndpointIngestRequest(BaseModel):
    tenant_id: Optional[str] = Field(default=None)
    hostname: str = Field(..., min_length=1, max_length=128)
    username: str = Field(..., min_length=1, max_length=128)
    ip_address: Optional[str] = Field(default=None)
    os_version: Optional[str] = Field(default="Windows 11 Pro 23H2")
    agent_version: Optional[str] = Field(default="2.0.0")
    shadow_ai_dns_hits: List[ShadowAiDnsHitItem] = Field(default_factory=list)
    risky_extensions: List[RiskyExtensionItem] = Field(default_factory=list)
    box_audit: CloudSyncAuditPayload = Field(default_factory=CloudSyncAuditPayload)
    onedrive_audit: Optional[CloudSyncAuditPayload] = Field(default=None)
    heartbeat: Optional[Dict[str, Any]] = Field(default=None)
    timestamp: Optional[str] = None


class SmbScanRequest(BaseModel):
    tenant_id: Optional[str] = Field(default=None)
    regulatory_profile: Optional[Literal["ANTAI_LEY81", "SBP_001_2022", "SALUD_LEY68"]] = None
    server_ip: str = Field(..., description="IP del Windows Server en la LAN")
    username: Optional[str] = Field(default="")
    password: Optional[str] = Field(default="")
    domain: Optional[str] = Field(default="WORKGROUP")
    port: int = Field(default=445, ge=1, le=65535)
    max_depth: int = Field(default=3, ge=1, le=6)
    max_file_mb: int = Field(default=10, ge=1, le=50)
    simulate_if_unreachable: bool = Field(
        default=False,
        description="Debe ser explícitamente true para generar simulación cuando el servidor SMB no responde.",
    )


class DbScanRequest(BaseModel):
    tenant_id: Optional[str] = Field(default=None)
    regulatory_profile: Optional[Literal["ANTAI_LEY81", "SBP_001_2022", "SALUD_LEY68"]] = None
    db_type: Literal["sqlite", "postgresql", "mysql", "mssql", "oracle"] = "sqlite"
    sqlite_path: Optional[str] = Field(default=None)
    host: Optional[str] = Field(default=None)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    database: Optional[str] = Field(default=None)
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    dsn: Optional[str] = Field(default=None)
    repository_name: Optional[str] = Field(default=None)
    sample_limit: int = Field(default=200, ge=1, le=2000)
    tables: Optional[List[str]] = Field(default=None)


class SyncNowRequest(BaseModel):
    tenant_id: Optional[str] = None
    include_heartbeats: bool = True
    include_dns: bool = False
