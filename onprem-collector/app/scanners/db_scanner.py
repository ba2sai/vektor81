"""
Relational database PII & retention scanner supporting SQLite, PostgreSQL, MySQL, MSSQL, and Oracle.
"""

from __future__ import annotations

import re
import sqlite3
import time
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..pii_bridge import (
    analyze_text,
    compute_finding_severity,
    evaluate_retention_violation,
)

DATE_COLUMN_PRIORITY = (
    "fecha_baja",
    "created_at",
    "fecha_registro",
    "fecha_creacion",
    "fecha_ingreso",
    "fecha_alta",
    "date_created",
    "updated_at",
)

SUPPORTED_DB_TYPES = frozenset({"sqlite", "postgresql", "mysql", "mssql", "oracle"})


def _parse_datetime_value(val: Any) -> Optional[datetime]:
    """Parse common SQL date/timestamp values into timezone-aware UTC datetime."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, date):
        return datetime(val.year, val.month, val.day, tzinfo=timezone.utc)
    if isinstance(val, (int, float)) and val > 100_000_000:
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        except (ValueError, OSError):
            return None

    raw = str(val).strip()
    if not raw:
        return None

    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
    ):
        try:
            dt = datetime.strptime(raw[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _quote_identifier(db_type: str, identifier: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.$-]+", identifier):
        raise ValueError(f"Unsafe SQL identifier rejected: {identifier!r}")
    parts = identifier.split(".")
    if db_type == "mysql":
        return ".".join(f"`{p}`" for p in parts)
    if db_type == "mssql":
        return ".".join(f"[{p}]" for p in parts)
    return ".".join(f'"{p}"' for p in parts)


class DbScanner:
    """Inspects relational databases locally in memory and emits masked FindingBatchPayload."""

    def __init__(
        self,
        db_type: str = "sqlite",
        sqlite_path: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        database: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        dsn: Optional[str] = None,
        repository_name: Optional[str] = None,
        regulatory_profile: str = "ANTAI_LEY81",
        tenant_id: str = "default-tenant",
        sample_limit: int = 200,
    ):
        self.db_type = (db_type or "sqlite").strip().lower()
        if self.db_type not in SUPPORTED_DB_TYPES:
            raise ValueError(
                f"Unsupported db_type '{self.db_type}'. Expected one of {sorted(SUPPORTED_DB_TYPES)}."
            )
        self.sqlite_path = sqlite_path
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self.dsn = dsn
        self.repository_name = repository_name
        self.regulatory_profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
        self.tenant_id = tenant_id or "default-tenant"
        self.sample_limit = max(1, min(int(sample_limit), 2000))

    def _target_label(self) -> str:
        if self.repository_name:
            return self.repository_name
        if self.db_type == "sqlite":
            return Path(self.sqlite_path or "sqlite.db").name
        db_part = self.database or self.dsn or "db"
        host_part = self.host or "localhost"
        return f"{self.db_type}://{host_part}/{db_part}"

    def _connect(self):
        if self.db_type == "sqlite":
            if not self.sqlite_path:
                raise ValueError("sqlite_path is required when db_type='sqlite'")
            path = Path(self.sqlite_path)
            if not path.exists():
                raise FileNotFoundError(f"SQLite file not found: {self.sqlite_path}")
            try:
                uri = f"{path.resolve().as_uri()}?mode=ro"
                return sqlite3.connect(uri, uri=True, timeout=10)
            except sqlite3.Error:
                return sqlite3.connect(str(path), timeout=10)

        if self.db_type == "postgresql":
            try:
                import psycopg2  # type: ignore[import-untyped]

                if self.dsn:
                    return psycopg2.connect(self.dsn, connect_timeout=8)
                return psycopg2.connect(
                    host=self.host or "localhost",
                    port=self.port or 5432,
                    dbname=self.database,
                    user=self.username,
                    password=self.password,
                    connect_timeout=8,
                )
            except ImportError:
                try:
                    import psycopg  # type: ignore[import-untyped]

                    if self.dsn:
                        return psycopg.connect(self.dsn, connect_timeout=8)
                    return psycopg.connect(
                        host=self.host or "localhost",
                        port=self.port or 5432,
                        dbname=self.database,
                        user=self.username,
                        password=self.password,
                        connect_timeout=8,
                    )
                except ImportError as exc:
                    raise RuntimeError(
                        "PostgreSQL driver missing: install 'psycopg2-binary' or 'psycopg'."
                    ) from exc

        if self.db_type == "mysql":
            try:
                import pymysql  # type: ignore[import-untyped]
            except ImportError as exc:
                raise RuntimeError("MySQL driver missing: install 'pymysql'.") from exc
            return pymysql.connect(
                host=self.host or "localhost",
                port=self.port or 3306,
                database=self.database,
                user=self.username or "",
                password=self.password or "",
                connect_timeout=8,
                read_timeout=15,
            )

        if self.db_type == "mssql":
            try:
                import pyodbc  # type: ignore[import-untyped]

                conn_str = self.dsn or (
                    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                    f"SERVER={self.host or 'localhost'},{self.port or 1433};"
                    f"DATABASE={self.database or ''};"
                    f"UID={self.username or ''};PWD={self.password or ''};"
                    "Encrypt=yes;TrustServerCertificate=yes;"
                )
                return pyodbc.connect(conn_str, timeout=8)
            except ImportError:
                try:
                    import pymssql  # type: ignore[import-untyped]

                    return pymssql.connect(
                        server=self.host or "localhost",
                        port=self.port or 1433,
                        database=self.database,
                        user=self.username,
                        password=self.password,
                        login_timeout=8,
                    )
                except ImportError as exc:
                    raise RuntimeError(
                        "MSSQL driver missing: install 'pyodbc' or 'pymssql'."
                    ) from exc

        if self.db_type == "oracle":
            try:
                import oracledb  # type: ignore[import-untyped]
            except ImportError as exc:
                raise RuntimeError("Oracle driver missing: install 'oracledb'.") from exc
            dsn_val = self.dsn or f"{self.host or 'localhost'}:{self.port or 1521}/{self.database or 'ORCL'}"
            return oracledb.connect(user=self.username, password=self.password, dsn=dsn_val)

        raise ValueError(f"Unsupported db_type: {self.db_type}")

    def _list_tables(self, cursor: Any) -> List[str]:
        if self.db_type == "sqlite":
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            return [row[0] for row in cursor.fetchall()]

        if self.db_type == "postgresql":
            cursor.execute(
                "SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('pg_catalog', 'information_schema') "
                "AND table_type = 'BASE TABLE' ORDER BY table_schema, table_name"
            )
            return [
                f"{row[0]}.{row[1]}" if row[0] != "public" else row[1]
                for row in cursor.fetchall()
            ]

        if self.db_type == "mysql":
            cursor.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name"
            )
            return [row[0] for row in cursor.fetchall()]

        if self.db_type == "mssql":
            cursor.execute(
                "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
                "WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_SCHEMA, TABLE_NAME"
            )
            return [
                f"{row[0]}.{row[1]}" if row[0].lower() != "dbo" else row[1]
                for row in cursor.fetchall()
            ]

        if self.db_type == "oracle":
            cursor.execute("SELECT table_name FROM user_tables ORDER BY table_name")
            return [row[0] for row in cursor.fetchall()]

        return []

    def _sample_table(self, cursor: Any, table_name: str) -> Tuple[List[str], List[Tuple[Any, ...]]]:
        quoted = _quote_identifier(self.db_type, table_name)
        if self.db_type == "mssql":
            sql = f"SELECT TOP {self.sample_limit} * FROM {quoted}"
        elif self.db_type == "oracle":
            sql = f"SELECT * FROM {quoted} FETCH FIRST {self.sample_limit} ROWS ONLY"
        else:
            sql = f"SELECT * FROM {quoted} LIMIT {self.sample_limit}"

        cursor.execute(sql)
        col_names = [desc[0] for desc in (cursor.description or [])]
        rows = cursor.fetchall()
        return col_names, rows

    def run_scan(self, tables: Optional[List[str]] = None) -> Dict[str, Any]:
        """Connect, inspect tables/columns, detect Panama PII & retention violations, and mask results."""
        start_time = time.perf_counter()
        scan_id = f"db-{uuid.uuid4().hex[:12]}"
        repo_label = self._target_label()
        now_dt = datetime.now(timezone.utc)
        detected_iso = now_dt.isoformat()

        conn = self._connect()
        tables_scanned = 0
        rows_sampled = 0
        tables_with_pii = set()

        # Keyed by (table_name, column_name, entity_type)
        aggregated: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        try:
            cursor = conn.cursor()
            available_tables = self._list_tables(cursor)
            if tables:
                requested = set(tables)
                target_tables = [t for t in available_tables if t in requested]
            else:
                target_tables = available_tables

            for table_name in target_tables:
                tables_scanned += 1
                col_names, rows = self._sample_table(cursor, table_name)
                if not col_names or not rows:
                    continue

                lower_cols = [c.lower() for c in col_names]
                date_col_indices: List[int] = [
                    lower_cols.index(dc)
                    for dc in DATE_COLUMN_PRIORITY
                    if dc in lower_cols
                ]

                for row in rows:
                    rows_sampled += 1

                    # Determine row retention age from lifecycle date columns
                    row_age_days: Optional[int] = None
                    for idx in date_col_indices:
                        parsed_dt = _parse_datetime_value(row[idx])
                        if parsed_dt is not None:
                            row_age_days = max(0, (now_dt - parsed_dt).days)
                            break

                    # Format row into contextual string while tracking column character spans
                    segments: List[str] = []
                    spans: List[Tuple[int, int, str]] = []
                    cursor_pos = 0
                    for col_name, val in zip(col_names, row):
                        if val is None:
                            continue
                        val_str = str(val).strip()
                        if not val_str:
                            continue
                        seg = f"{col_name}: {val_str}"
                        if segments:
                            cursor_pos += 3  # " | "
                        start_idx = cursor_pos
                        end_idx = start_idx + len(seg)
                        segments.append(seg)
                        spans.append((start_idx, end_idx, col_name))
                        cursor_pos = end_idx

                    if not segments:
                        continue

                    row_text = " | ".join(segments)
                    pii_findings = analyze_text(row_text, regulatory_profile=self.regulatory_profile)
                    if not pii_findings:
                        continue

                    tables_with_pii.add(table_name)
                    row_has_clinical = any(
                        f.entity_type == "PA_DATO_SENSIBLE_SALUD" for f in pii_findings
                    )

                    for finding in pii_findings:
                        matched_col = col_names[0]
                        for sp_start, sp_end, sp_col in spans:
                            if sp_start <= finding.start < sp_end:
                                matched_col = sp_col
                                break

                        is_clinical_entity = (
                            finding.entity_type == "PA_DATO_SENSIBLE_SALUD" or row_has_clinical
                        )
                        ret_violation = evaluate_retention_violation(
                            self.regulatory_profile,
                            row_age_days,
                            is_clinical=is_clinical_entity,
                        )
                        sev = compute_finding_severity(
                            finding.entity_type,
                            finding.is_sensitive,
                            ret_violation,
                        )

                        key = (table_name, matched_col, finding.entity_type)
                        entry = aggregated.get(key)
                        if entry is None:
                            aggregated[key] = {
                                "source_type": "SQL_DB",
                                "repository_name": repo_label,
                                "location_path": f"{table_name}.{matched_col}",
                                "entity_type": finding.entity_type,
                                "masked_sample": finding.masked_value,
                                "value_sha256": finding.value_sha256,
                                "match_count": 1,
                                "is_sensitive": bool(finding.is_sensitive),
                                "severity": sev,
                                "retention_age_days": row_age_days,
                                "retention_violation": ret_violation,
                                "detected_at": detected_iso,
                            }
                        else:
                            entry["match_count"] += 1
                            if finding.is_sensitive:
                                entry["is_sensitive"] = True
                            if ret_violation:
                                entry["retention_violation"] = True
                            if row_age_days is not None:
                                prev_age = entry["retention_age_days"]
                                entry["retention_age_days"] = (
                                    row_age_days if prev_age is None else max(prev_age, row_age_days)
                                )
                            if severity_rank[sev] > severity_rank[entry["severity"]]:
                                entry["severity"] = sev
        finally:
            try:
                conn.close()
            except Exception:
                pass

        findings_list = list(aggregated.values())
        sensitive_count = sum(1 for f in findings_list if f["is_sensitive"])
        retention_violations_count = sum(1 for f in findings_list if f["retention_violation"])
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)

        return {
            "scan_id": scan_id,
            "tenant_id": self.tenant_id,
            "regulatory_profile": self.regulatory_profile,
            "db_type": self.db_type,
            "target_label": repo_label,
            "tables_scanned": tables_scanned,
            "rows_sampled": rows_sampled,
            "tables_with_pii_count": len(tables_with_pii),
            "findings_count": len(findings_list),
            "sensitive_findings_count": sensitive_count,
            "retention_violations_count": retention_violations_count,
            "is_simulated": False,
            "findings": findings_list,
            "finding_batch_payload": {
                "tenant_id": self.tenant_id,
                "scan_id": scan_id,
                "scanner_layer": "DB_CONNECTOR",
                "is_simulated": False,
                "total_assets_scanned": tables_scanned,
                "scan_duration_ms": elapsed_ms,
                "findings": findings_list,
            },
            "scan_duration_ms": elapsed_ms,
        }
