"""
Modelos SQLAlchemy y esquemas Pydantic para Vektor81:
Shadow AI & Ley 81 Audit Appliance (Panamá).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    create_engine,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/vektor81_audit.db")

os.makedirs("./data", exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 15} if DATABASE_URL.startswith("sqlite") else {},
)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        # WAL permite lecturas y escrituras concurrentes (ej. 200 PCs reportando por GPO + generación de PDF)
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=15000;")
        # 64MB de caché en RAM para acelerar agregaciones del Dashboard
        cursor.execute("PRAGMA cache_size=-64000;")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# =====================================================================
# MODELOS ORM (SQLite)
# =====================================================================

class EndpointAsset(Base):
    """Inventario maestro de estaciones de trabajo Windows auditadas."""
    __tablename__ = "endpoint_assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(128), unique=True, index=True, nullable=False)
    username = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=True)
    os_version = Column(String(128), default="Windows 10/11 Pro")
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Resumen rápido de última auditoría para consultas O(1) en el Dashboard
    dns_hits_count = Column(Integer, default=0)
    risky_extensions_count = Column(Integer, default=0)
    box_exposed_files = Column(Integer, default=0)
    box_dlp_active = Column(Boolean, default=False)
    endpoint_risk_score = Column(Float, default=0.0)

    ingest_logs = relationship(
        "EndpointIngestLog",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="desc(EndpointIngestLog.created_at)",
    )


class EndpointIngestLog(Base):
    """Historial inmutable de reportes recibidos desde el agente PowerShell."""
    __tablename__ = "endpoint_ingest_logs"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("endpoint_assets.id"), nullable=False)
    hostname = Column(String(128), index=True, nullable=False)
    username = Column(String(128), nullable=False)
    shadow_ai_dns_hits = Column(JSON, default=list)       # Lista de dicts: [{domain, count, category, process}]
    risky_extensions = Column(JSON, default=list)         # Lista de dicts: [{id, name, browser, permissions, has_all_urls}]
    box_audit = Column(JSON, default=dict)                # Dict: {installed, sync_path, sensitive_files_count, dlp_enabled, sample_files}
    created_at = Column(DateTime, default=utcnow, index=True)

    asset = relationship("EndpointAsset", back_populates="ingest_logs")


class SmbScanResult(Base):
    """Resultado de auditorías ejecutadas contra servidores Windows Server (SMB/CIFS)."""
    __tablename__ = "smb_scan_results"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String(64), index=True, nullable=False)
    server_name = Column(String(128), nullable=True)
    auth_mode = Column(String(32), default="Guest/Anonymous")  # Guest/Anonymous o Authenticated
    guest_access_allowed = Column(Boolean, default=False)
    total_shares = Column(Integer, default=0)
    critical_shares_found = Column(JSON, default=list)         # Ej: ["Planilla", "Contratos", "Finanzas"]
    total_office_pdf_files = Column(Integer, default=0)
    files_with_pii_count = Column(Integer, default=0)
    cedula_matches_count = Column(Integer, default=0)
    ruc_matches_count = Column(Integer, default=0)
    email_matches_count = Column(Integer, default=0)
    findings_detail = Column(JSON, default=list)               # Detalle por archivo/share con muestras enmascaradas
    scan_duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow, index=True)


class DnsAuditSnapshot(Base):
    """Snapshots consolidados desde AdGuard Home (/control/querylog)."""
    __tablename__ = "dns_audit_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    total_queries_inspected = Column(Integer, default=0)
    shadow_ai_hits_total = Column(Integer, default=0)
    by_client_ip = Column(JSON, default=dict)                  # { "192.168.1.45": {"total": 18, "domains": [...]} }
    by_category = Column(JSON, default=dict)                   # { "LLM Chat": 42, "Document Processing": 19, ... }
    by_domain = Column(JSON, default=dict)                     # { "chatgpt.com": 30, "ilovepdf.com": 15 }
    created_at = Column(DateTime, default=utcnow, index=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


# =====================================================================
# ESQUEMAS PYDANTIC (Request / Response Validation)
# =====================================================================

class ShadowAiDnsHitItem(BaseModel):
    domain: str = Field(..., examples=["chatgpt.com"])
    count: int = Field(default=1, ge=1)
    category: Optional[str] = Field(default="LLM General")
    last_timestamp: Optional[str] = None


class RiskyExtensionItem(BaseModel):
    extension_id: str = Field(..., examples=["efaidnbmnnnibpcajpcglclefindmkaj"])
    name: str = Field(..., examples=["Free AI PDF Summarizer & Chat"])
    browser: str = Field(default="Chrome", examples=["Chrome", "Edge"])
    version: Optional[str] = "1.0.0"
    permissions: List[str] = Field(default_factory=list, examples=[["<all_urls>", "tabs", "storage"]])
    has_all_urls: bool = Field(default=True)


class BoxAuditPayload(BaseModel):
    installed: bool = Field(default=False)
    sync_path: Optional[str] = Field(default=None, examples=["C:\\Users\\jperez\\Box"])
    total_synced_files: int = Field(default=0, ge=0)
    sensitive_files_count: int = Field(default=0, ge=0)
    dlp_enabled: bool = Field(default=False)
    sample_files: List[str] = Field(default_factory=list)


class EndpointIngestRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=128, examples=["PC-CONTABILIDAD-01"])
    username: str = Field(..., min_length=1, max_length=128, examples=["CONTABILIDAD\\mrodriguez"])
    ip_address: Optional[str] = Field(default=None, examples=["192.168.10.24"])
    os_version: Optional[str] = Field(default="Windows 11 Pro 23H2")
    shadow_ai_dns_hits: List[ShadowAiDnsHitItem] = Field(default_factory=list)
    risky_extensions: List[RiskyExtensionItem] = Field(default_factory=list)
    box_audit: BoxAuditPayload = Field(default_factory=BoxAuditPayload)


class SmbScanRequest(BaseModel):
    server_ip: str = Field(..., description="IP del Windows Server en la LAN", examples=["192.168.10.5"])
    username: Optional[str] = Field(default="", description="Vacío para probar Guest/Anónimo")
    password: Optional[str] = Field(default="", description="Contraseña SMB")
    domain: Optional[str] = Field(default="WORKGROUP", description="Dominio Active Directory o Workgroup")
    port: int = Field(default=445, description="Puerto SMB (445 o 139)")
    max_depth: int = Field(default=3, ge=1, le=5)
    sample_kb_limit: int = Field(default=16, ge=4, le=64, description="Kilobytes iniciales a inspeccionar por archivo")
    simulate_if_unreachable: bool = Field(
        default=True,
        description="En modo demo/POC, si el servidor SMB no responde en la LAN, retorna hallazgos realistas claramente marcados como simulación.",
    )
